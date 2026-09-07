plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
    id("io.github.takahirom.roborazzi")
}

// Robolectric downloads android-all through its own maven fetcher, which
// bypasses gradle and therefore the nix sandbox. Let gradle resolve the
// jar and hand it over in offline mode.
val androidAll: Configuration by configurations.creating
val robolectricJars by tasks.registering(Copy::class) {
    from(androidAll)
    into(layout.buildDirectory.dir("robolectric"))
}

android {
    namespace = "io.thalheim.tincr"
    compileSdk = 35
    buildToolsVersion = "35.0.0" // must exist in the nix SDK (read-only)

    defaultConfig {
        applicationId = "io.thalheim.tincr"
        minSdk = 24
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        ndk.abiFilters += listOf("arm64-v8a", "x86_64")
    }

    // tincd ships as jniLibs/<abi>/libtincd.so. Exec from
    // nativeLibraryDir needs extracted files (API 29 noexec).
    packaging.jniLibs.useLegacyPackaging = true

    buildFeatures.compose = true
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions.jvmTarget = "17"
    testOptions.unitTests.isIncludeAndroidResources = true
    testOptions.unitTests.all {
        it.dependsOn(robolectricJars)
        it.systemProperty("robolectric.offline", "true")
        it.systemProperty("robolectric.dependency.dir", robolectricJars.get().destinationDir.path)
    }
}


dependencies {
    implementation(platform("androidx.compose:compose-bom:2025.04.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
    debugImplementation("androidx.compose.ui:ui-test-manifest")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.robolectric:robolectric:4.14.1")
    // The SDK jar robolectric 4.14.1 expects for @Config(sdk = 35).
    androidAll("org.robolectric:android-all-instrumented:15-robolectric-12650502-i7")
    testImplementation("androidx.compose.ui:ui-test-junit4")
    testImplementation("io.github.takahirom.roborazzi:roborazzi:1.43.1")
    testImplementation("io.github.takahirom.roborazzi:roborazzi-compose:1.43.1")

    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
}
