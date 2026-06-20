package io.caleidoscode.doublethink.data

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * Stores per-topic shared secrets (S) encrypted at rest via EncryptedSharedPreferences
 * (AES-256-GCM, key in the Android Keystore). Only the secret lives here, keyed by
 * topic id; derived keys are never persisted (they are cheap to recompute from S).
 *
 * The broker stays payload-blind, but the device boundary is a real trust edge: anyone
 * with the unlocked device and app data could read S. EncryptedSharedPreferences raises
 * that bar to a Keystore-bound key rather than plaintext on disk.
 */
class SecretVault(context: Context) {
    private val prefs = run {
        val ctx = context.applicationContext
        val masterKey = MasterKey.Builder(ctx)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        EncryptedSharedPreferences.create(
            ctx,
            "doublethink_secrets",
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    }

    fun put(topicId: String, secret: String) {
        prefs.edit().putString(topicId, secret).apply()
    }

    fun get(topicId: String): String? = prefs.getString(topicId, null)

    fun remove(topicId: String) {
        prefs.edit().remove(topicId).apply()
    }
}
