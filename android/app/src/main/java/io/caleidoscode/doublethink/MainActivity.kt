package io.caleidoscode.doublethink

import android.Manifest
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import io.caleidoscode.doublethink.ui.AboutScreen
import io.caleidoscode.doublethink.ui.AddTopicScreen
import io.caleidoscode.doublethink.ui.AppViewModel
import io.caleidoscode.doublethink.ui.TopicListScreen

/**
 * Single-activity host. Screen switching is plain Compose state (no navigation library).
 * On launch it requests notification permission, prompts to disable battery optimization
 * (so the foreground service survives Doze better), and starts the subscription service.
 */
class MainActivity : ComponentActivity() {
    private val vm: AppViewModel by viewModels()

    private val requestNotifications =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { /* result surfaced by the OS */ }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            requestNotifications.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
        vm.ensureServiceRunning()
        maybePromptBatteryOptimization()

        setContent {
            DoublethinkTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    AppRoot(vm)
                }
            }
        }
    }

    private fun maybePromptBatteryOptimization() {
        // Sends the user to the OS dialog to exempt this app, improving delivery in Doze.
        // Best-effort; some OEMs ignore it. Guarded so we only ask when not already exempt.
        try {
            val pm = getSystemService(android.os.PowerManager::class.java)
            if (pm != null && !pm.isIgnoringBatteryOptimizations(packageName)) {
                @Suppress("BatteryLife")
                startActivity(
                    Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:$packageName")),
                )
            }
        } catch (_: Exception) {
            // No-op if the intent is unavailable on this device.
        }
    }

    companion object {
        /** Intent extra carrying the topic id a notification tap should open. */
        const val EXTRA_TOPIC_ID = "io.caleidoscode.doublethink.TOPIC_ID"
    }
}

private enum class Screen { LIST, ADD, ABOUT }

@Composable
private fun AppRoot(vm: AppViewModel) {
    var screen by remember { mutableStateOf(Screen.LIST) }
    var addStatus by remember { mutableStateOf<String?>(null) }
    var pendingSecret by remember { mutableStateOf(vm.newSecret()) }
    val topics by vm.topics.collectAsState()

    when (screen) {
        Screen.LIST -> TopicListScreen(
            topics = topics,
            onAdd = { addStatus = null; pendingSecret = vm.newSecret(); screen = Screen.ADD },
            onAbout = { screen = Screen.ABOUT },
            onRemove = { vm.removeTopic(it) },
        )
        Screen.ABOUT -> AboutScreen(sealedPublicKey = remember { vm.boxPublicKeyBase64() })
        Screen.ADD -> AddTopicScreen(
            initialSecret = pendingSecret,
            statusText = addStatus,
            onCreateEncrypted = { name, server, channel, secret, role ->
                addStatus = "Creating channel..."
                vm.addEncryptedTopic(name, server, channel, secret, role) { result ->
                    when (result) {
                        is AppViewModel.AddResult.Ok -> screen = Screen.LIST
                        is AppViewModel.AddResult.RateLimited ->
                            addStatus = "The broker is rate limited; wait a minute and try again."
                        is AppViewModel.AddResult.Error -> addStatus = "Could not add: ${result.message}"
                    }
                }
            },
            onCreatePlaintext = { name, server, channel ->
                vm.addPlaintextTopic(name, server, channel); screen = Screen.LIST
            },
            onCreateSealed = { name, server, channel ->
                vm.addSealedTopic(name, server, channel); screen = Screen.LIST
            },
            onCancel = { screen = Screen.LIST },
        )
    }
}

@Composable
fun DoublethinkTheme(content: @Composable () -> Unit) {
    MaterialTheme(content = content)
}
