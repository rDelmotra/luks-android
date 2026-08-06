plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}

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
        versionCode = 1
        versionName = "0.1.0"

        // The Rust build produces arm64 by default. Anything else in the APK
        // would be a stale copy, so be explicit rather than shipping whatever
        // happens to be in jniLibs.
        ndk {
            abiFilters += "arm64-v8a"
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
val checkNoWriteCodeInRelease by tasks.registering {
    val soFile = layout.projectDirectory.file("src/main/jniLibs/arm64-v8a/libluks_jni.so")
    doLast {
        val needle = "nativeWriteFile".toByteArray(Charsets.US_ASCII)
        val hay = soFile.asFile.readBytes()

        var found = false
        outer@ for (i in 0..hay.size - needle.size) {
            for (j in needle.indices) {
                if (hay[i + j] != needle[j]) continue@outer
            }
            found = true
            break
        }

        if (found) {
            throw GradleException(
                """
                ${soFile.asFile.relativeTo(rootDir)} exports nativeWriteFile.

                This is a release build, and a release build must not contain
                the write path at all. The .so currently in jniLibs was built
                with --write. Rebuild it without, from the repo root:

                    tools/build-android-libs.sh

                (--write is debug-only and the script already refuses to pair
                it with --release; this catches the other order — a leftover
                debug .so being packaged into a release APK.)
                """.trimIndent()
            )
        }
    }
}

tasks.matching { it.name.startsWith("merge") && it.name.endsWith("ReleaseJniLibFolders") }
    .configureEach { dependsOn(checkNoWriteCodeInRelease) }

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

    debugImplementation(libs.androidx.compose.ui.tooling)
}
