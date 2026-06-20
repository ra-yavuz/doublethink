package io.caleidoscode.doublethink.broker

import io.caleidoscode.doublethink.crypto.ChannelCrypto
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

/**
 * The non-streaming broker HTTP calls: create an ephemeral private channel, and
 * publish to a plaintext topic. Streaming (live receive) is handled by
 * EncryptedConnection (WS) and PlaintextConnection (SSE).
 */
class BrokerApi(private val client: OkHttpClient) {

    sealed class Result {
        object Ok : Result()
        object RateLimited : Result()       // HTTP 429
        object Conflict : Result()          // HTTP 409 (channel already exists)
        data class Error(val code: Int, val body: String) : Result()
        data class Failure(val cause: Throwable) : Result()
    }

    /**
     * Create an ephemeral private channel: POST <base>/channel with the channel id
     * and the base32 registration key (K_auth) derived from the secret. The secret S
     * itself is never sent. retain is false (retained channels need an account, out of
     * scope for v1).
     */
    suspend fun createEncryptedChannel(
        baseUrl: String,
        channelId: String,
        secret: String,
    ): Result = withContext(Dispatchers.IO) {
        val regKey = ChannelCrypto.registrationKey(secret)
        val payload = CreateChannelReq(channel = channelId, authKey = regKey, retain = false)
        val body = JSON_CODEC.encodeToString(CreateChannelReq.serializer(), payload)
            .toRequestBody(JSON)
        val req = Request.Builder()
            .url(baseUrl.trimEnd('/') + "/channel")
            .post(body)
            .build()
        execute(req)
    }

    /** Publish a raw message to a plaintext topic: POST <base>/publish/<topic>. */
    suspend fun publishPlaintext(
        baseUrl: String,
        topic: String,
        message: String,
    ): Result = withContext(Dispatchers.IO) {
        val req = Request.Builder()
            .url(baseUrl.trimEnd('/') + "/publish/" + topic)
            .post(message.toRequestBody(TEXT))
            .build()
        execute(req)
    }

    private fun execute(req: Request): Result = try {
        client.newCall(req).execute().use { resp ->
            when (resp.code) {
                in 200..299 -> Result.Ok
                429 -> Result.RateLimited
                409 -> Result.Conflict
                else -> Result.Error(resp.code, resp.body?.string().orEmpty())
            }
        }
    } catch (t: Throwable) {
        Result.Failure(t)
    }

    @Serializable
    private data class CreateChannelReq(
        @SerialName("channel") val channel: String,
        @SerialName("auth_key") val authKey: String,
        @SerialName("retain") val retain: Boolean,
    )

    companion object {
        private val JSON = "application/json; charset=utf-8".toMediaType()
        private val TEXT = "text/plain; charset=utf-8".toMediaType()
        private val JSON_CODEC = Json { encodeDefaults = true }
    }
}
