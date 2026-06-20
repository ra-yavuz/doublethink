package io.caleidoscode.doublethink.notify

import android.app.Notification
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import io.caleidoscode.doublethink.MainActivity

/**
 * Builds and posts message notifications. Encrypted topics show a decrypted preview
 * when the topic allows it (showPreview), else a generic line; an undecryptable
 * message shows a "could not decrypt" line so the user still knows traffic arrived.
 * Messages on one topic share a group so a burst collapses rather than spamming.
 *
 * The caller is responsible for NOT calling this for the app's own echoed messages
 * (own-echo suppression lives in the connection manager).
 */
class Notifier(private val ctx: Context) {

    /**
     * Post a message notification.
     *
     * @param topicId      the topic UUID (selects the per-topic channel + group)
     * @param topicName    display name shown as the title
     * @param body         the text to show (already preview-trimmed by the caller), or null
     * @param showPreview  whether this topic permits showing message content
     * @param decryptOk    false if an encrypted message could not be decrypted
     * @param notifyId     a stable id so re-delivery updates rather than duplicates
     */
    fun postMessage(
        topicId: String,
        topicName: String,
        body: String?,
        showPreview: Boolean,
        decryptOk: Boolean,
        notifyId: Int,
    ) {
        val text = when {
            !decryptOk -> "New message (could not decrypt)"
            !showPreview || body.isNullOrEmpty() -> "New message"
            else -> body
        }
        val tap = PendingIntent.getActivity(
            ctx, topicId.hashCode(),
            Intent(ctx, MainActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP)
                putExtra(MainActivity.EXTRA_TOPIC_ID, topicId)
            },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val n = NotificationCompat.Builder(ctx, NotificationChannels.topicChannelId(topicId))
            .setSmallIcon(android.R.drawable.stat_notify_chat)
            .setContentTitle(topicName)
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setGroup(NotificationChannels.topicChannelId(topicId))
            .setAutoCancel(true)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setContentIntent(tap)
            .build()
        safeNotify(notifyId, n)
    }

    fun postError(topicName: String, reason: String, notifyId: Int) {
        val n = NotificationCompat.Builder(ctx, NotificationChannels.ERRORS)
            .setSmallIcon(android.R.drawable.stat_notify_error)
            .setContentTitle("$topicName: connection problem")
            .setContentText(reason)
            .setAutoCancel(true)
            .build()
        safeNotify(notifyId, n)
    }

    private fun safeNotify(id: Int, n: Notification) {
        // POST_NOTIFICATIONS (API 33+) may be denied; NotificationManagerCompat.notify
        // is a no-op without it. We check to avoid a SecurityException on some OEMs.
        val mgr = NotificationManagerCompat.from(ctx)
        if (mgr.areNotificationsEnabled()) {
            try {
                mgr.notify(id, n)
            } catch (_: SecurityException) {
                // Permission revoked between check and post; nothing to do.
            }
        }
    }
}
