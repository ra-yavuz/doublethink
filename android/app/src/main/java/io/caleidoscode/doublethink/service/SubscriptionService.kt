package io.caleidoscode.doublethink.service

import android.app.Notification
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import io.caleidoscode.doublethink.MainActivity
import io.caleidoscode.doublethink.data.SecretVault
import io.caleidoscode.doublethink.data.TopicStore
import io.caleidoscode.doublethink.model.Topic
import io.caleidoscode.doublethink.notify.NotificationChannels
import io.caleidoscode.doublethink.notify.Notifier
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.launch
import okhttp3.OkHttpClient
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * The always-on foreground service. It holds live broker connections for every enabled
 * topic and raises a system notification the moment a message arrives that this app did
 * not send. It runs as a foreground service so it survives the app being backgrounded.
 *
 * HONEST LIMIT: doublethink has no push gateway, so deep-Doze / app-killed delivery is not
 * guaranteed. This service is the ceiling without a third-party push service (which would
 * break the broker-blind model). The ongoing notification reflects that it is listening.
 */
class SubscriptionService : Service() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val client by lazy {
        OkHttpClient.Builder()
            .pingInterval(30, TimeUnit.SECONDS) // keep WS alive through NATs
            .retryOnConnectionFailure(true)
            .build()
    }
    private lateinit var topicStore: TopicStore
    private lateinit var vault: SecretVault
    private lateinit var notifier: Notifier
    private lateinit var manager: ConnectionManager
    private val notifyIdSeq = AtomicInteger(1000)

    override fun onCreate() {
        super.onCreate()
        topicStore = TopicStore(this)
        vault = SecretVault(this)
        notifier = Notifier(this)
        NotificationChannels.ensureFixedChannels(this)

        manager = ConnectionManager(
            scope = scope,
            client = client,
            secretFor = { topic -> vault.get(topic.id) },
            sink = serviceSink,
        )

        startForegroundStatus(0)

        // React to topic-list changes: ensure channels exist, then sync connections.
        topicStore.topics.onEach { topics ->
            topics.forEach { NotificationChannels.ensureTopicChannel(this, it.id, it.displayName) }
            manager.sync(topics)
            startForegroundStatus(topics.count { it.enabled })
        }.launchIn(scope)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Restarted by the OS after a kill (best-effort; not guaranteed under deep Doze).
        return START_STICKY
    }

    private val serviceSink = object : ConnectionManager.MessageSink {
        override fun onStatus(topicId: String, status: ConnStatus, detail: String?) {
            // Status is surfaced to the UI via a future shared flow; for now the ongoing
            // notification is the user-visible signal. Errors raise a one-off notification.
            if (status == ConnStatus.FAILED) {
                scope.launch {
                    val name = topicStore.snapshot().firstOrNull { it.id == topicId }?.displayName ?: topicId
                    notifier.postError(name, detail ?: "connection failed", notifyIdSeq.incrementAndGet())
                }
            }
        }

        override fun onIncoming(topic: Topic, envelopeId: String, type: String, text: String?, decryptOk: Boolean, seq: Long?) {
            notifier.postMessage(
                topicId = topic.id,
                topicName = topic.displayName,
                body = text,
                showPreview = topic.showPreview,
                decryptOk = decryptOk,
                notifyId = (topic.id + envelopeId).hashCode(),
            )
            if (seq != null) scope.launch { topicStore.setLastSeenSeq(topic.id, seq) }
        }
    }

    private fun startForegroundStatus(activeCount: Int) {
        val tap = android.app.PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            android.app.PendingIntent.FLAG_IMMUTABLE,
        )
        val text = if (activeCount == 0) "Watching for messages" else "Watching $activeCount topic(s)"
        val n: Notification = NotificationCompat.Builder(this, NotificationChannels.SERVICE_STATUS)
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setContentTitle("doublethink")
            .setContentText(text)
            .setOngoing(true)
            .setContentIntent(tap)
            .build()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(SERVICE_NOTIFICATION_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(SERVICE_NOTIFICATION_ID, n)
        }
    }

    override fun onDestroy() {
        manager.stopAll()
        scope.cancel()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    companion object {
        private const val SERVICE_NOTIFICATION_ID = 1

        fun start(context: Context) {
            val intent = Intent(context, SubscriptionService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, SubscriptionService::class.java))
        }
    }
}
