package io.thalheim.tincr

import androidx.compose.runtime.Composable
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onRoot
import com.github.takahirom.roborazzi.captureRoboImage
import io.thalheim.tincr.ui.AdvancedScreen
import io.thalheim.tincr.ui.Device
import io.thalheim.tincr.ui.HomeState
import io.thalheim.tincr.ui.JoinScreen
import io.thalheim.tincr.ui.Link
import io.thalheim.tincr.ui.MainScreen
import io.thalheim.tincr.ui.OnboardingScreen
import io.thalheim.tincr.ui.Tab
import io.thalheim.tincr.ui.TincrTheme
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

// `gradle recordRoborazziDebug` renders every screen state to
// build/outputs/roborazzi/*.png. There are no goldens to diff against.
// The test proves each state composes, and the PNGs are for review.
@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [35], qualifiers = "w393dp-h852dp-xxhdpi")
class ScreenshotTest {
    @get:Rule
    val compose = createComposeRule()

    private val family = HomeState(
        network = "Family network",
        link = Link.Connected,
        inviter = "Jörg",
        devices = listOf(
            Device("Jörg’s server", "Backups & photos", online = true),
            Device("Mama’s phone", "", online = true, self = true),
            Device("Papa’s laptop", "Last seen yesterday", online = false),
            Device("Living room TV", "Media", online = true),
        ),
    )

    private fun shot(name: String, content: @Composable () -> Unit) {
        compose.setContent { TincrTheme { content() } }
        compose.onRoot().captureRoboImage("build/outputs/roborazzi/$name.png")
    }

    @Composable
    private fun main(state: HomeState, tab: Tab) =
        MainScreen(state, tab, onTab = {}, onToggle = {}, onHelpReport = {}, onSettings = {})

    @Test fun onboarding() = shot("1_onboarding") { OnboardingScreen({}, {}) }
    @Test fun join() = shot("1_join") { JoinScreen("tinc://join/example.org/" + "x".repeat(48), {}, false, null, {}, {}) }
    @Test fun joinError() =
        shot("1_join_error") { JoinScreen("nope", {}, false, "This is not an invitation link.", {}, {}) }
    @Test fun joinBusy() = shot("1_join_busy") { JoinScreen("", {}, true, null, {}, {}) }
    @Test fun homeConnected() = shot("2_home_connected") { main(family, Tab.Home) }
    @Test fun homeOff() = shot("2_home_off") { main(family.copy(link = Link.Off), Tab.Home) }
    @Test fun homeConnecting() = shot("2_home_connecting") { main(family.copy(link = Link.Connecting), Tab.Home) }
    @Test fun devices() = shot("3_devices") { main(family, Tab.Devices) }
    @Test fun devicesNoInternet() =
        shot("3_devices_no_internet") { main(family.copy(notice = Problems.noInternet()), Tab.Devices) }
    @Test fun homePeerUnreachable() =
        shot("2_home_peer_unreachable") { main(family.copy(link = Link.Connecting, notice = Problems.peerUnreachable("Dad", 40, "Trying to connect to gate (203.0.113.5 port 655)\nTimeout from gate")), Tab.Home) }
    @Test fun homeNewPhone() =
        shot("2_home_new_phone") { main(family.copy(link = Link.Off, notice = Problems.newPhone("Dad")), Tab.Home) }
    @Test fun help() = shot("4_help") { main(family, Tab.Help) }
    @Test fun advanced() = shot("5_advanced") {
        AdvancedScreen("tincd 0.1.0 starting\nListening on 0.0.0.0 port 12655\nConnected to gate", onBack = {})
    }
}
