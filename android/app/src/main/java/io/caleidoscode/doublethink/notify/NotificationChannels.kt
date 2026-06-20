package io.caleidoscode.doublethink.notify

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import androidx.core.content.getSystemService

/**
 * Notification channel management. One channel per topic (so the user gets native
 * per-topic control of importance, sound, and muting), plus two fixed channels: the
 * low-importance ongoing service status, and an errors channel for connection
 * failures. Channels exist from API 26 (the app's minSdk), so no version guard is
 * needed.
 */
object NotificationChannels {
    const val SERVICE_STATUS = "service_status"
    const val ERRORS = "errors"
    private const val TOPIC_PREFIX = "topic_"

    fun topicChannelId(topicId: String): String = TOPIC_PREFIX + topicId

    private fun manager(ctx: Context): NotificationManager = ctx.getSystemService()!!

    /** Create the two fixed channels. Idempotent (createNotificationChannel updates). */
    fun ensureFixedChannels(ctx: Context) {
        val nm = manager(ctx)
        nm.createNotificationChannel(
            NotificationChannel(
                SERVICE_STATUS, "Listening status", NotificationManager.IMPORTANCE_LOW,
            ).apply { description = "The ongoing notification while doublethink is watching your topics." },
        )
        nm.createNotificationChannel(
            NotificationChannel(
                ERRORS, "Connection problems", NotificationManager.IMPORTANCE_DEFAULT,
            ).apply { description = "Alerts when a topic cannot connect (for example, a wrong secret)." },
        )
    }

    /** Create (or update the display name of) a topic's message channel. */
    fun ensureTopicChannel(ctx: Context, topicId: String, displayName: String) {
        manager(ctx).createNotificationChannel(
            NotificationChannel(
                topicChannelId(topicId), displayName, NotificationManager.IMPORTANCE_HIGH,
            ).apply { description = "Messages on the \"$displayName\" topic." },
        )
    }

    fun removeTopicChannel(ctx: Context, topicId: String) {
        manager(ctx).deleteNotificationChannel(topicChannelId(topicId))
    }
}
