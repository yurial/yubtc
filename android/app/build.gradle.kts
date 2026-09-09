// yubtc Android — :app build file.
//
// Compose app with Material 3 + Navigation. Loads the yubtc-core
// cdylib from `jniLibs/<abi>/libyubtc_core.so`; the per-ABI artefacts
// are copied there by the `copyNativeLibs` task below.
//
// Min SDK 30: matches the NDK r27 target API used by
// `.github/workflows/release.yml`. Compile/target SDK 34.

import java.util.Properties
import org.gradle.api.tasks.Exec

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}

// --- Release signing credentials ------------------------------------
//
// `keystore.properties` lives at the Android project root
// (`android/keystore.properties`). It is gitignored; the
// `keystore.properties.example` template documents the format.
// CI decodes the `YBTC_KEYSTORE_PROPERTIES` secret (base64 of this
// file's contents) into the same path before invoking gradle.
//
// `hasReleaseKeystore` is the gate used by both `signingConfigs`
// and `buildTypes.release`: when false, the release config is
// skipped and the build type falls back to the debug keystore.
//
// These are evaluated at file-load time and must come *before*
// the `android { }` block below that consumes them.

val keystorePropertiesFile = rootProject.file("keystore.properties")
val keystoreProperties = Properties().apply {
    if (keystorePropertiesFile.exists()) {
        keystorePropertiesFile.inputStream().use { load(it) }
    }
}

val hasReleaseKeystore = listOf("storeFile", "storePassword", "keyAlias", "keyPassword")
    .all { field -> keystoreProperties.getProperty(field)?.isNotBlank() == true }

android {
    namespace = "io.yubtc.wallet"
    compileSdk = 34

    sourceSets["main"].kotlin.srcDirs(
        // Generated UniFFI facade — single source of truth lives in
        // `bindings/kotlin/uniffi/yubtc_core/`. The CI `bindings`
        // job regenerates it and fails the build if this checked-in
        // copy drifts from the cdylib's metadata.
        "${rootDir}/../bindings/kotlin",
    )

    defaultConfig {
        applicationId = "io.yubtc.wallet"
        minSdk = 30
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0"

        // ABI matrix: only the three targets the .so is built for.
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }
    }

    // --- Release signing -------------------------------------------------
    //
    // Reads `android/keystore.properties` (gitignored) for release
    // credentials. When the file is absent or any of its fields is
    // blank, the release build type falls back to the debug keystore
    // so `./gradlew assembleRelease` still succeeds locally for a
    // developer who hasn't set up a real keystore. CI populates the
    // file from the `YBTC_KEYSTORE_PROPERTIES` secret.
    //
    // Expected properties (all four required for the release config
    // to activate):
    //
    //   storeFile      — path to a JKS / PKCS12 keystore, resolved
    //                    relative to the Android project root. Use
    //                    an absolute path for keys kept outside the
    //                    repo.
    //   storePassword  — keystore password (non-blank).
    //   keyAlias       — alias of the signing key inside the store.
    //   keyPassword    — key password (may equal storePassword).
    //
    // Any blank field disables the release config; this avoids
    // accidentally signing a production APK with placeholder values.
    signingConfigs {
        if (hasReleaseKeystore) {
            create("release") {
                storeFile = rootProject.file(keystoreProperties.getProperty("storeFile"))
                storePassword = keystoreProperties.getProperty("storePassword")
                keyAlias = keystoreProperties.getProperty("keyAlias")
                keyPassword = keystoreProperties.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        debug {
            isMinifyEnabled = false
            isDebuggable = true
        }
        release {
            isMinifyEnabled = false
            isShrinkResources = false
            // Wire the release config when present, fall back to the
            // debug keystore otherwise (developer smoke builds). The
            // fallback means the resulting APK is *not* suitable for
            // distribution — it carries the debug certificate which
            // the Play Store rejects.
            signingConfig = if (hasReleaseKeystore) {
                signingConfigs.getByName("release")
            } else {
                signingConfigs.getByName("debug")
            }
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
    }

    packaging {
        jniLibs {
            // Strip .so debug symbols to shrink the APK.
            keepDebugSymbols += listOf()
            useLegacyPackaging = false
        }
    }
}

// --- Native library copy -------------------------------------------
//
// `cargo build --target <triple> --release` writes the cdylib into
// `<repo>/target/<triple>/release/libyubtc_core.so`. Because `core`
// is a member of the root workspace (`Cargo.toml`) and nothing sets
// `build.target-dir`, cargo resolves to the workspace-root `target/`
// whether it is invoked from the repo root or from `core/` — this is
// the one canonical location, so no fallback paths are needed. The
// `copyNativeLibs` task picks the cdylibs up from there and copies
// them into `app/jniLibs/<abi>/` where AGP picks them up at packaging
// time.
//
// CI runs the Rust build before Gradle, so the artifacts are
// guaranteed to exist. Locally you can run `./gradlew copyNativeLibs`
// after `cargo build` (or skip and let the gradle task shell out to
// `cargo build` itself).

val abiMap = mapOf(
    "arm64-v8a" to "aarch64-linux-android",
    "armeabi-v7a" to "armv7-linux-androideabi",
    "x86_64" to "x86_64-linux-android",
)

tasks.register("copyNativeLibs") {
    group = "yubtc"
    description = "Copy libyubtc_core.so for each ABI from target/<triple>/release into jniLibs/<abi>/."

    // Resolve every path to a plain java.io.File *now* (configuration
    // time). Calling `file()` / touching `Project` inside `doLast` is
    // rejected by the configuration cache (org.gradle.configuration-
    // cache=true in gradle.properties) and fails every Gradle
    // invocation on Gradle 8.x with `problems=fail`.
    // `rootProject` is the `android/` project, so `../target` is the
    // cargo workspace root target dir.
    val workspaceTargetDir = rootProject.file("../target")
    val copies = abiMap.map { (abi, triple) ->
        val src = File(workspaceTargetDir, "$triple/release/libyubtc_core.so")
        val dstDir = File(projectDir, "src/main/jniLibs/$abi")
        Triple(src, File(dstDir, "libyubtc_core.so"), triple)
    }

    doLast {
        copies.forEach { (src, dst, triple) ->
            require(src.exists()) {
                "Missing native library: $src. Build it with `cargo build --release --target $triple -p yubtc-core --lib` from the repo root (Phase 4)."
            }
            dst.parentFile.mkdirs()
            src.copyTo(dst, overwrite = true)
        }
    }
}

tasks.named("preBuild") {
    dependsOn("copyNativeLibs")
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.lifecycle.process)
    implementation(libs.androidx.navigation.compose)

    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.material3)

    implementation(libs.qrcode.kotlin)

    // UniFFI Kotlin facade (`bindings/kotlin/`, compiled into this
    // module via the extra srcDir above) talks to the cdylib through
    // JNA. Version pinned per the uniffi 0.32 Kotlin guide; `@aar`
    // pulls the Android packaging that bundles libjnidispatch.so.
    implementation("net.java.dev.jna:jna:5.13.0@aar")

    debugImplementation(libs.androidx.compose.ui.tooling)

    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.rules)
    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(libs.espresso.core)
}
