package io.caleidoscode.doublethink.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.FilterChip
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import io.caleidoscode.doublethink.crypto.Role
import io.caleidoscode.doublethink.model.Topic
import io.caleidoscode.doublethink.model.TopicMode

/** The topic list: each topic with its mode, plus actions to add or open About. */
@Composable
fun TopicListScreen(
    topics: List<Topic>,
    onAdd: () -> Unit,
    onAbout: () -> Unit,
    onRemove: (Topic) -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text("Topics", style = androidx.compose.material3.MaterialTheme.typography.headlineSmall)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(onClick = onAbout) { Text("About") }
                Button(onClick = onAdd) { Text("Add") }
            }
        }
        if (topics.isEmpty()) {
            Text("No topics yet. Tap Add to subscribe to one.")
        } else {
            LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                items(topics, key = { it.id }) { topic ->
                    Card(modifier = Modifier.fillMaxWidth()) {
                        Column(modifier = Modifier.padding(12.dp)) {
                            Text(topic.displayName, style = androidx.compose.material3.MaterialTheme.typography.titleMedium)
                            Text(
                                "${if (topic.mode == TopicMode.ENCRYPTED) "Encrypted" else "Plaintext"} · ${topic.channelId}",
                                style = androidx.compose.material3.MaterialTheme.typography.bodySmall,
                            )
                            Text(topic.serverBaseUrl, style = androidx.compose.material3.MaterialTheme.typography.bodySmall)
                            TextButton(onClick = { onRemove(topic) }) { Text("Remove") }
                        }
                    }
                }
            }
        }
    }
}

/**
 * Add a topic. Encrypted mode generates or accepts a shared secret and a send role;
 * plaintext mode just needs a topic name. The server defaults to the public broker.
 */
@Composable
fun AddTopicScreen(
    initialSecret: String,
    onCreateEncrypted: (name: String, server: String, channel: String, secret: String, role: Role) -> Unit,
    onCreatePlaintext: (name: String, server: String, channel: String) -> Unit,
    onCancel: () -> Unit,
    statusText: String?,
    modifier: Modifier = Modifier,
) {
    var encrypted by remember { mutableStateOf(true) }
    var name by remember { mutableStateOf("") }
    var server by remember { mutableStateOf(Topic.DEFAULT_SERVER) }
    var channel by remember { mutableStateOf("") }
    var secret by remember { mutableStateOf(initialSecret) }
    var role by remember { mutableStateOf(Role.A) }

    Column(
        modifier = modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Add topic", style = androidx.compose.material3.MaterialTheme.typography.headlineSmall)

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(selected = encrypted, onClick = { encrypted = true }, label = { Text("Encrypted") })
            FilterChip(selected = !encrypted, onClick = { encrypted = false }, label = { Text("Plaintext") })
        }

        OutlinedTextField(name, { name = it }, label = { Text("Display name") }, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(server, { server = it }, label = { Text("Server") }, modifier = Modifier.fillMaxWidth(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri))
        OutlinedTextField(channel, { channel = it }, label = { Text("Channel / topic id") }, modifier = Modifier.fillMaxWidth())

        if (encrypted) {
            OutlinedTextField(secret, { secret = it }, label = { Text("Shared secret") }, modifier = Modifier.fillMaxWidth())
            Text("Keep this secret safe and share it only with the other party. It is never sent to the broker.",
                style = androidx.compose.material3.MaterialTheme.typography.bodySmall)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("I send as:")
                FilterChip(selected = role == Role.A, onClick = { role = Role.A }, label = { Text("A") })
                FilterChip(selected = role == Role.B, onClick = { role = Role.B }, label = { Text("B") })
            }
        }

        if (statusText != null) Text(statusText, style = androidx.compose.material3.MaterialTheme.typography.bodyMedium)

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = onCancel) { Text("Cancel") }
            Button(
                onClick = {
                    if (encrypted) onCreateEncrypted(name, server.trim(), channel.trim(), secret.trim(), role)
                    else onCreatePlaintext(name, server.trim(), channel.trim())
                },
                enabled = channel.isNotBlank() && (!encrypted || secret.isNotBlank()),
            ) { Text("Add") }
        }
    }
}
