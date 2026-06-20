# doublethink Android client

A sideloadable Android app for the [doublethink](../README.md) broker. Subscribe to one or
more topics, push and pull messages, and get a system notification the moment a message
arrives on a topic that you did not send yourself.

By default it talks to the public broker at `https://api.caleidoscode.io`; you can point any
topic at your own doublethink server.

## What it does

- **Encrypted private channels.** You hold a shared secret. The app derives the channel keys
  on-device (exactly as the broker's reference clients do), authenticates over WebSocket with a
  challenge/response, and seals and opens message payloads locally. The broker only ever sees
  ciphertext; the secret is never sent to it.
- **Plaintext public topics.** ntfy-style: publish over HTTP, subscribe over Server-Sent Events.
  No secret.
- **Multiple topics at once,** each with its own connection.
- **Notifications on arrival.** A foreground service holds the live connections and raises a
  per-topic system notification when a message comes in. Messages you sent yourself are not
  notified back to you.

## How encrypted topics work (two parties)

An encrypted topic is shared between two parties with distinct roles, **A** and **B**. When you
add an encrypted topic you choose which role you send as; reading auto-detects. Two devices that
both pick the same role cannot read each other. The shared secret is the only gate: anyone who
holds it can join and read the channel, and it is never transmitted to the broker.

## Install

Download the APK from the [releases page](https://github.com/ra-yavuz/doublethink/releases)
and sideload it (you will need to allow installation from your browser or file manager). The APK
is signed; verify the `SHA256SUMS` if you wish.

## Delivery limitation (read this)

doublethink has no push gateway, and adding one would mean handing message-arrival signals to a
third party, which breaks the broker-blind design. So this app receives by keeping a live
connection in a foreground service. While the service runs you get notifications instantly. When
Android suspends the app in deep sleep, delivery can be delayed or missed until you open the app
again. Disabling battery optimization for the app (the app prompts you on first run) makes
delivery considerably more reliable. There is no way to guarantee wake-from-deep-sleep without a
push service.

## Building

Built with the Android toolchain in a container (no host install): Temurin 21, Android SDK 36,
build-tools 36.0.0, Gradle 8.13, Kotlin 2.3.21, AGP 8.7.3. From `android/`:

```
./gradlew :app:assembleDebug :app:testDebugUnitTest
```

The crypto is verified byte-for-byte against the Go broker's client crypto by `CryptoParityTest`
(golden vectors generated from the broker's own `internal/clientcrypto`).

## Disclaimer

This software is provided "as is", without warranty of any kind, express or implied. You use it
entirely at your own risk. The author, Ramazan Yavuz, accepts no liability for any loss, damage,
or data exposure arising from its use.
