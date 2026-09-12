plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}

// Resolved before `android { }` so the assemble-time warning below can see it too.
val releaseKeystoreFile = (findProperty("luksReleaseStoreFile") as String?)?.let(::file)
val hasReleaseSigningKey = releaseKeystoreFile?.exists() == true

android {
    namespace = "dev.luksandroid"
    compileSdk = 36

    defaultConfig {
        applicationId = "dev.luksandroid"
        // API 29 matches the NDK linker level the Rust side is built against
        // (DEC-012). Raising it here without rebuilding the .so at the same
        // level produces a library that links but may call symbols the older
        // bionic lacks.
        minSdk = 29
        targetSdk = 36
        versionCode = 2
        versionName = "0.2.0"

        // The Rust build produces arm64 by default. Anything else in the APK
        // would be a stale copy, so be explicit rather than shipping whatever
        // happens to be in jniLibs.
        ndk {
            abiFilters += "arm64-v8a"
        }
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    // Release signing, from properties that never enter the repository.
    //
    // Put these in ~/.gradle/gradle.properties (user-level, outside the project),
    // or supply them as ORG_GRADLE_PROJECT_* environment variables in CI:
    //
    //     luksReleaseStoreFile=/absolute/path/to/luks-release.jks
    //     luksReleaseStorePassword=...
    //     luksReleaseKeyAlias=luks-release
    //     luksReleaseKeyPassword=...
    //
    // On Android the signing key *is* the application's identity: an update is
    // accepted only if it carries the same signature. The debug keystore is the
    // wrong key for that job — not because a debug-signed APK is a debug build
    // (this one is minified, shrunk and not debuggable), but because that
    // keystore is disposable by design. The SDK regenerates it silently when it
    // is missing, and the day that happens `dev.luksandroid` can never be
    // updated in place again: every user has to uninstall and reinstall. Its
    // only protection is the documented constant password `android`, which is a
    // poor root of trust for the update chain of a tool that handles LUKS
    // passphrases.
    signingConfigs {
        if (hasReleaseSigningKey) {
            create("release") {
                storeFile = releaseKeystoreFile
                storePassword = findProperty("luksReleaseStorePassword") as String?
                keyAlias = findProperty("luksReleaseKeyAlias") as String?
                keyPassword = findProperty("luksReleaseKeyPassword") as String?
            }
        }
    }

    buildTypes {
        debug {
            isMinifyEnabled = false
        }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
            // Falls back to the debug key so a checkout with no keystore still
            // builds — but says so every time, because a silent fallback is how
            // a debug-signed APK reaches users in the first place.
            signingConfig = if (hasReleaseSigningKey) {
                signingConfigs.getByName("release")
            } else {
                signingConfigs.getByName("debug")
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlin {
        compilerOptions {
            jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
        }
    }

    buildFeatures {
        compose = true
        // For BuildConfig.DEBUG, which gates all diagnostic logging. A release
        // build must not write what is on an encrypted drive into the system
        // log — see the Trace object in MainActivity.
        buildConfig = true
    }

    packaging {
        jniLibs {
            // The .so is already stripped by Cargo's release profile. Leaving
            // it uncompressed lets the loader mmap it straight from the APK.
            useLegacyPackaging = false
        }
    }
    testOptions {
        unitTests.isReturnDefaultValues = true
    }
}

// TreeImportTraceTest compares TreeImporter's recorded operation sequence
// against the checked-in traces the Rust kernel oracle replays. Gradle cannot
// see that dependency on its own: editing a trace leaves the test task
// up-to-date, so it does not rerun and a drifted fixture passes. Measured --
// a deliberately corrupted trace reported BUILD SUCCESSFUL until --rerun-tasks
// forced it. Declaring the directory as an input closes that.
tasks.withType<Test>().configureEach {
    inputs.dir(rootProject.layout.projectDirectory.dir("../fixtures/transfer"))
        .withPropertyName("transferTraceFixtures")
        .withPathSensitivity(PathSensitivity.RELATIVE)
}

// Gradle has no idea Cargo exists. Rather than a plugin that breaks on every
// AGP bump, the contract is: run tools/build-android-libs.sh, then build. This
// check turns "forgot to run it" from an UnsatisfiedLinkError at runtime into a
// build failure that says what to do.
val checkNativeLibs by tasks.registering {
    val soFile = layout.projectDirectory.file("src/main/jniLibs/arm64-v8a/libluks_jni.so")
    doLast {
        if (!soFile.asFile.exists()) {
            throw GradleException(
                """
                Missing ${soFile.asFile.relativeTo(rootDir)}

                The Rust library is built outside Gradle. From the repo root:
                    tools/build-android-libs.sh
                """.trimIndent()
            )
        }
    }
}

tasks.matching { it.name.startsWith("merge") && it.name.endsWith("JniLibFolders") }
    .configureEach { dependsOn(checkNativeLibs) }

// The claim this project makes about safety is that a release build cannot
// corrupt a drive because the instruction is not in the binary. Until this
// task existed that claim was unchecked at the only place it matters: the .so
// in jniLibs is packaged into *both* variants, checkNativeLibs above asserted
// only that the file exists, and tools/verify-no-write-code.sh inspects
// target/debug — never jniLibs. So the one artifact that actually ships was
// the one nothing looked at, and a release APK built after any
// `build-android-libs.sh --debug --write` shipped the write path.
//
// A JNI entry point is #[no_mangle] and non-generic, so its name is in the
// .so's dynamic symbol table as literal ASCII or the function does not exist.
// A byte search finds it without needing llvm-nm on PATH — which matters,
// because a check that silently skips when a tool is missing is how the last
// symbol check came to prove nothing for months.
//
// Deliberately release-only. A debug .so built with --write is the entire
// point of that flag, and failing there would make write testing impossible.
val allowWriteInRelease = project.hasProperty("allowWriteInRelease") && project.property("allowWriteInRelease") == "true"

val checkNoWriteCodeInRelease by tasks.registering {
    val soFile = layout.projectDirectory.file("src/main/jniLibs/arm64-v8a/libluks_jni.so")
    doLast {
        if (allowWriteInRelease) {
            println("NOTE: allowWriteInRelease=true is active; write symbols are permitted in this release build.")
            return@doLast
        }
        val needles = listOf(
            "nativeBenchmarkWrite",
            "nativeWriteFile",
            "nativeBeginFile",
            "nativeBeginFileStreaming",
            "nativeWriteChunk",
            "nativeWriteChunkWithCancel",
            "nativeFinishFile",
            "nativeCommitActiveBatch",
            "nativeCloseWriter",
            "nativeDeleteFile",
            "nativeCreateDirectory",
            "nativeRename",
        ).map { it to it.toByteArray(Charsets.US_ASCII) }
        val hay = soFile.asFile.readBytes()
        check(hay.size > 100_000) {
            "${soFile.asFile.relativeTo(rootDir)} is suspiciously small (${hay.size} bytes); expected a valid compiled ELF shared library"
        }

        var foundSymbol: String? = null
        for ((name, needle) in needles) {
            outer@ for (i in 0..hay.size - needle.size) {
                for (j in needle.indices) {
                    if (hay[i + j] != needle[j]) continue@outer
                }
                foundSymbol = name
                break
            }
            if (foundSymbol != null) break
        }

        if (foundSymbol != null) {
            throw GradleException(
                """
                ${soFile.asFile.relativeTo(rootDir)} exports $foundSymbol.

                This is a release build, and a release build must not contain
                the write path at all. The .so currently in jniLibs was built
                with --write. Rebuild it without, from the repo root:

                    tools/build-android-libs.sh

                (This task is the ONLY thing preventing a write-enabled .so
                from reaching a release APK. An earlier version of this
                message claimed build-android-libs.sh refuses to pair --write
                with --release; it does not, and never did — `--write` alone
                builds a write-enabled release-profile .so deliberately, for
                local benchmarking. So this check is the safety boundary, not
                a backstop for one.)
                """.trimIndent()
            )
        }
    }
}

tasks.matching { it.name.startsWith("merge") && it.name.endsWith("ReleaseJniLibFolders") }
    .configureEach { dependsOn(checkNoWriteCodeInRelease) }

// A release APK carrying the debug signature is installable and looks fine, so
// nothing else in the build would ever mention it. Say it at `lifecycle` level,
// which survives `--console=plain -q`, rather than leaving it to be discovered
// by whoever eventually runs `apksigner verify --print-certs`.
val warnIfDebugSignedRelease by tasks.registering {
    doLast {
        if (!hasReleaseSigningKey) {
            logger.lifecycle(
                """
                |
                |  ============================================================
                |   WARNING: this release APK is signed with the DEBUG key.
                |
                |   On Android the signing key is the app's identity. That
                |   keystore is regenerated silently if it is ever deleted, and
                |   when it changes no build can update an installed copy of
                |   dev.luksandroid — every user must uninstall and reinstall.
                |
                |   Set luksReleaseStoreFile / luksReleaseStorePassword /
                |   luksReleaseKeyAlias / luksReleaseKeyPassword in
                |   ~/.gradle/gradle.properties. Do it before distributing:
                |   the migration cost grows with every install.
                |  ============================================================
                |
                """.trimMargin()
            )
        }
    }
}

tasks.matching { it.name.matches(Regex("^(assemble|bundle|package)Release$")) }
    .configureEach { dependsOn(warnIfDebugSignedRelease) }

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.activity.compose)

    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.material3)
    implementation("androidx.compose.material:material-icons-core")

    debugImplementation(libs.androidx.compose.ui.tooling)

    testImplementation(libs.junit)
    testImplementation("org.json:json:20240303")
    androidTestImplementation(libs.junit)
    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(libs.androidx.test.runner)
}

