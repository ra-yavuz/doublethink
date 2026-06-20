package io.caleidoscode.doublethink.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import io.caleidoscode.doublethink.broker.BrokerApi
import io.caleidoscode.doublethink.crypto.ChannelCrypto
import io.caleidoscode.doublethink.crypto.Role
import io.caleidoscode.doublethink.data.SecretVault
import io.caleidoscode.doublethink.data.TopicStore
import io.caleidoscode.doublethink.model.Topic
import io.caleidoscode.doublethink.model.TopicMode
import io.caleidoscode.doublethink.service.SubscriptionService
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import okhttp3.OkHttpClient
import java.util.UUID

/**
 * Holds app state for the UI: the topic list (from [TopicStore]) and the operations to
 * add, remove, and send. It owns secret storage and channel creation, and (re)starts the
 * foreground subscription service whenever the topic set changes so connections track the
 * configured topics.
 */
class AppViewModel(app: Application) : AndroidViewModel(app) {
    private val store = TopicStore(app)
    private val vault = SecretVault(app)
    private val http = OkHttpClient()
    private val api = BrokerApi(http)

    val topics: StateFlow<List<Topic>> =
        store.topics.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    /** A fresh secret the add-topic screen can show for a new encrypted channel. */
    fun newSecret(): String = ChannelCrypto.generateSecret()

    sealed class AddResult {
        object Ok : AddResult()
        object RateLimited : AddResult()
        data class Error(val message: String) : AddResult()
    }

    /**
     * Add an encrypted topic: store the secret, create the channel on the broker (idempotent
     * if it already exists), persist the config, and (re)start the service.
     */
    fun addEncryptedTopic(
        displayName: String,
        serverBaseUrl: String,
        channelId: String,
        secret: String,
        sendRole: Role,
        onResult: (AddResult) -> Unit,
    ) {
        viewModelScope.launch {
            val id = UUID.randomUUID().toString()
            when (val r = api.createEncryptedChannel(serverBaseUrl, channelId, secret)) {
                is BrokerApi.Result.Ok, is BrokerApi.Result.Conflict -> {
                    // Conflict = channel already exists; fine, we just join it with our secret.
                    vault.put(id, secret)
                    store.upsert(
                        Topic(
                            id = id, displayName = displayName.ifBlank { channelId },
                            serverBaseUrl = serverBaseUrl, channelId = channelId,
                            mode = TopicMode.ENCRYPTED, sendRole = sendRole,
                        ),
                    )
                    SubscriptionService.start(getApplication())
                    onResult(AddResult.Ok)
                }
                is BrokerApi.Result.RateLimited -> onResult(AddResult.RateLimited)
                is BrokerApi.Result.Error -> onResult(AddResult.Error("HTTP ${r.code}"))
                is BrokerApi.Result.Failure -> onResult(AddResult.Error(r.cause.message ?: "network error"))
            }
        }
    }

    /** Add a plaintext topic: no secret, no channel creation; just subscribe via SSE. */
    fun addPlaintextTopic(displayName: String, serverBaseUrl: String, channelId: String) {
        viewModelScope.launch {
            val id = UUID.randomUUID().toString()
            store.upsert(
                Topic(
                    id = id, displayName = displayName.ifBlank { channelId },
                    serverBaseUrl = serverBaseUrl, channelId = channelId, mode = TopicMode.PLAINTEXT,
                ),
            )
            SubscriptionService.start(getApplication())
        }
    }

    fun removeTopic(topic: Topic) {
        viewModelScope.launch {
            store.remove(topic.id)
            vault.remove(topic.id)
            SubscriptionService.start(getApplication())
        }
    }

    /** Publish to a plaintext topic over HTTP. Encrypted send goes through the service WS. */
    fun publishPlaintext(topic: Topic, text: String, onDone: (Boolean) -> Unit) {
        viewModelScope.launch {
            val ok = api.publishPlaintext(topic.serverBaseUrl, topic.channelId, text) is BrokerApi.Result.Ok
            onDone(ok)
        }
    }

    fun ensureServiceRunning() = SubscriptionService.start(getApplication())
}
