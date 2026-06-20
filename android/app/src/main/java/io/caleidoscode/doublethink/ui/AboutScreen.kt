package io.caleidoscode.doublethink.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

/**
 * About + the mandatory liability disclaimer (a required surface for every public
 * project). Also states the honest delivery limitation plainly.
 */
@Composable
fun AboutScreen(modifier: Modifier = Modifier, sealedPublicKey: String? = null) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("doublethink", style = MaterialTheme.typography.headlineSmall)
        Text(
            "A sideloadable client for the doublethink broker by Ramazan Yavuz. Subscribe to " +
                "encrypted private channels or plaintext topics and get a notification when a " +
                "message arrives.",
            style = MaterialTheme.typography.bodyMedium,
        )

        if (sealedPublicKey != null) {
            Text("Your sealed-inbox public key", style = MaterialTheme.typography.titleMedium)
            Text(
                "Publish this key (for example on a contact page). Anyone can use it to send " +
                    "you a sealed message that only this device can open. It is safe to share. " +
                    "Sealed messages are anonymous (the sender is not verified), and the broker " +
                    "sees only that and when a message arrived, never its contents.",
                style = MaterialTheme.typography.bodyMedium,
            )
            Text(sealedPublicKey, style = MaterialTheme.typography.bodySmall)
            Text(
                "Keep your key safe: if you lose this device without a backup, messages sealed " +
                    "to this key can no longer be read.",
                style = MaterialTheme.typography.bodySmall,
            )
        }

        Text("Delivery limitation", style = MaterialTheme.typography.titleMedium)
        Text(
            "doublethink has no push gateway, so this app keeps a live connection in a " +
                "foreground service to receive messages. While the service runs you get " +
                "notifications instantly. When the system suspends the app in deep sleep, " +
                "delivery can be delayed or missed until the app is opened again. Disabling " +
                "battery optimization for this app makes delivery more reliable.",
            style = MaterialTheme.typography.bodyMedium,
        )

        Text("Two-party encrypted channels", style = MaterialTheme.typography.titleMedium)
        Text(
            "An encrypted topic is shared between two parties with distinct roles (A and B). " +
                "Both sides reading each other requires opposite roles. The shared secret is " +
                "never sent to the broker.",
            style = MaterialTheme.typography.bodyMedium,
        )

        Text("Disclaimer", style = MaterialTheme.typography.titleMedium)
        Text(
            "This software is provided \"as is\", without warranty of any kind, express or " +
                "implied. You use it entirely at your own risk. The author accepts no " +
                "liability for any loss, damage, or data exposure arising from its use.",
            style = MaterialTheme.typography.bodyMedium,
        )
    }
}
