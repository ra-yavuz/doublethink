package io.caleidoscode.doublethink.data

import android.content.Context
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import io.caleidoscode.doublethink.crypto.SealedBox

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

    // --- Sealed-box keypair (one per device, for SEALED inbox topics) ---
    //
    // A single Curve25519 keypair is stored under a reserved key (not a topic id),
    // base64 of publicKey||secretKey. The public key is what the user publishes (on a
    // contact page); the private key never leaves this vault except via an explicit
    // passphrase-encrypted backup the user chooses to export.

    /** Returns the device sealed-box keypair, generating and storing it on first use. */
    fun boxKeypair(): SealedBox.Keypair {
        prefs.getString(BOX_KEY, null)?.let { stored ->
            val raw = Base64.decode(stored, Base64.NO_WRAP)
            if (raw.size == SealedBox.PUBLICKEY_BYTES + SealedBox.SECRETKEY_BYTES) {
                return SealedBox.Keypair(
                    publicKey = raw.copyOfRange(0, SealedBox.PUBLICKEY_BYTES),
                    secretKey = raw.copyOfRange(SealedBox.PUBLICKEY_BYTES, raw.size),
                )
            }
        }
        val kp = SealedBox.generateKeypair()
        storeBoxKeypair(kp)
        return kp
    }

    /** True if a sealed-box keypair already exists (so the UI can avoid generating one early). */
    fun hasBoxKeypair(): Boolean = prefs.getString(BOX_KEY, null) != null

    /** Replace the stored keypair (used by backup import). */
    fun storeBoxKeypair(kp: SealedBox.Keypair) {
        val raw = kp.publicKey + kp.secretKey
        prefs.edit().putString(BOX_KEY, Base64.encodeToString(raw, Base64.NO_WRAP)).apply()
    }

    private companion object {
        const val BOX_KEY = "__box_keypair__"
    }
}
