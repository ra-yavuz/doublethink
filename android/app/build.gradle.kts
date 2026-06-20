import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.serialization)
}

android {
    namespace = "io.caleidoscode.doublethink"
    compileSdk = 36
    // Pin to the build-tools installed in the dev container / CI image. AGP 8.7.3
    // would otherwise default to 34.0.0, which is not installed and would be fetched
    // over the network (unreliable here); 36.0.0 is present.
    buildToolsVersion = "36.0.0"

    defaultConfig {
        applicationId = "io.caleidoscode.doublethink"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    signingConfigs {
        // Release signing from environment (set in CI from repo secrets). Absent locally,
        // in which case the release build is left unsigned and assembleDebug is used instead.
        val ksPath = System.getenv("ANDROID_KEYSTORE_PATH")
        if (ksPath != null) {
            create("release") {
                storeFile = file(ksPath)
                storePassword = System.getenv("ANDROID_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("ANDROID_KEY_ALIAS")
                keyPassword = System.getenv("ANDROID_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        debug {
            isMinifyEnabled = false
        }
        release {
            // Minification is off for this sideloaded APK: it is not needed for size
            // here, and R8 would otherwise fail on tink's compile-only errorprone
            // annotations (com.google.errorprone.annotations.*) that are not on the
            // runtime classpath. No minify means no missing-class R8 errors.
            isMinifyEnabled = false
            signingConfig = signingConfigs.findByName("release")
        }
    }

    lint {
        // The release build runs lintVital, whose NonNullableMutableLiveDataDetector
        // crashes with an IncompatibleClassChangeError on this AGP/lint combination
        // (a known lint-tool bug). We do not use LiveData; disable the detector and do
        // not abort the build on lint so a packaging build is never blocked by a lint bug.
        disable += "NullSafeMutableLiveData"
        abortOnError = false
        checkReleaseBuilds = false
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
    testOptions {
        unitTests {
            isIncludeAndroidResources = true
            isReturnDefaultValues = true
        }
    }
    packaging {
        resources {
            // Several dependencies (bcprov, jspecify, kotlin stdlib) ship the same
            // metadata/license files; keep the first and drop the duplicates so the
            // merged APK has one copy each.
            excludes += setOf(
                "META-INF/versions/9/OSGI-INF/MANIFEST.MF",
                "META-INF/{AL2.0,LGPL2.1}",
                "META-INF/DEPENDENCIES",
                "META-INF/*.kotlin_module",
            )
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

dependencies {
    // AndroidX + lifecycle
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.service)
    implementation(libs.androidx.activity.compose)

    // Compose
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.ui)
    implementation(libs.androidx.ui.graphics)
    implementation(libs.androidx.ui.tooling.preview)
    implementation(libs.androidx.material3)
    debugImplementation(libs.androidx.ui.tooling)

    // Networking / SSE
    implementation(libs.okhttp)
    implementation(libs.okhttp.sse)

    // Crypto
    implementation(libs.bouncycastle)
    // lazysodium-android pulls JNA transitively as a plain jar; we instead want the
    // JNA .aar variant (it bundles the native libs). Exclude the transitive plain jna
    // so only the aar provides com.sun.jna (otherwise both land on the classpath and
    // collide as duplicate classes).
    implementation(libs.lazysodium.android) {
        exclude(group = "net.java.dev.jna", module = "jna")
    }
    implementation(variantOf(libs.jna) { artifactType("aar") })

    // Serialization
    implementation(libs.kotlinx.serialization.json)

    // Persistence (no annotation processor; see libs.versions.toml note on KSP).
    implementation(libs.androidx.security.crypto)
    implementation(libs.androidx.datastore.preferences)

    // Coroutines
    implementation(libs.kotlinx.coroutines.android)

    // Unit tests (src/test). The crypto parity test reads classpath resources from
    // app/src/test/resources/ (e.g. vectors.json); SmokeTest proves the wiring.
    testImplementation(libs.junit)

    // Instrumented tests (src/androidTest). SecretBoxParityTest needs a device/emulator
    // because libsodium's native lib is not on the plain JVM classpath.
    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(libs.androidx.test.runner)
}
