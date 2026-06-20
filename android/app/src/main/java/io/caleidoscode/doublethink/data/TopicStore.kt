package io.caleidoscode.doublethink.data

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import io.caleidoscode.doublethink.crypto.Role
import io.caleidoscode.doublethink.model.Topic
import io.caleidoscode.doublethink.model.TopicMode
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json

private val Context.topicDataStore: DataStore<Preferences> by preferencesDataStore(name = "topics")

/**
 * Persists the (non-secret) topic list as a JSON blob in a Preferences DataStore. No
 * annotation processor (Room/KSP is unavailable on Kotlin 2.3.x). Secrets are NOT here;
 * they live in [SecretVault]. Exposes a Flow so the UI updates reactively.
 */
class TopicStore(private val context: Context) {
    private val key = stringPreferencesKey("topics_json")
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    val topics: Flow<List<Topic>> = context.topicDataStore.data.map { prefs ->
        decode(prefs[key])
    }

    suspend fun snapshot(): List<Topic> = decode(context.topicDataStore.data.first()[key])

    suspend fun upsert(topic: Topic) {
        mutate { list -> list.filter { it.id != topic.id } + topic }
    }

    suspend fun remove(topicId: String) {
        mutate { list -> list.filter { it.id != topicId } }
    }

    suspend fun setLastSeenSeq(topicId: String, seq: Long) {
        mutate { list -> list.map { if (it.id == topicId && seq > it.lastSeenSeq) it.copy(lastSeenSeq = seq) else it } }
    }

    private suspend fun mutate(transform: (List<Topic>) -> List<Topic>) {
        context.topicDataStore.edit { prefs ->
            val current = decode(prefs[key])
            prefs[key] = encode(transform(current))
        }
    }

    private val dtoListSerializer = ListSerializer(TopicDto.serializer())

    private fun encode(list: List<Topic>): String =
        json.encodeToString(dtoListSerializer, list.map { it.toDto() })

    private fun decode(raw: String?): List<Topic> {
        if (raw.isNullOrEmpty()) return emptyList()
        return runCatching { json.decodeFromString(dtoListSerializer, raw).map { it.toModel() } }
            .getOrDefault(emptyList())
    }

    @Serializable
    private data class TopicDto(
        val id: String,
        val displayName: String,
        val serverBaseUrl: String,
        val channelId: String,
        val mode: String,
        val sendRole: String = "A",
        val showPreview: Boolean = true,
        val lastSeenSeq: Long = 0,
        val enabled: Boolean = true,
    )

    private fun Topic.toDto() = TopicDto(
        id, displayName, serverBaseUrl, channelId, mode.name, sendRole.name, showPreview, lastSeenSeq, enabled,
    )

    private fun TopicDto.toModel() = Topic(
        id = id,
        displayName = displayName,
        serverBaseUrl = serverBaseUrl,
        channelId = channelId,
        mode = runCatching { TopicMode.valueOf(mode) }.getOrDefault(TopicMode.ENCRYPTED),
        sendRole = runCatching { Role.valueOf(sendRole) }.getOrDefault(Role.A),
        showPreview = showPreview,
        lastSeenSeq = lastSeenSeq,
        enabled = enabled,
    )
}
