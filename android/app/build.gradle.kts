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
