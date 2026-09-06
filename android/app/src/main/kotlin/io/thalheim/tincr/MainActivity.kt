package io.thalheim.tincr

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import io.thalheim.tincr.ui.AdvancedScreen
import io.thalheim.tincr.ui.HomeState
import io.thalheim.tincr.ui.Link
import io.thalheim.tincr.ui.MainScreen
import io.thalheim.tincr.ui.OnboardingScreen
import io.thalheim.tincr.ui.Tab
import io.thalheim.tincr.ui.TincrTheme
import kotlinx.coroutines.delay
import java.io.File

class MainActivity : ComponentActivity() {
    private val netDir get() = File(filesDir, "networks/default")
    private val consent = registerForActivityResult(StartActivityForResult()) {
        if (it.resultCode == RESULT_OK) startVpn()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { TincrTheme { App() } }
        // adb/test entry. Consent must be pre-granted via appops.
        if (intent.getBooleanExtra("autostart", false)) {
            prepareAndStart()
        }
    }

    @Composable
    private fun App() {
        var tab by remember { mutableStateOf(Tab.Home) }
        var advanced by remember { mutableStateOf(false) }
        var link by remember { mutableStateOf(Link.Off) }
        var log by remember { mutableStateOf("") }
        LaunchedEffect(Unit) {
            while (true) {
                link = if (TincrVpnService.running) Link.Connected else Link.Off
                val f = File(netDir, "tincd.log")
                log = if (f.isFile) f.readLines().takeLast(200).joinToString("\n") else "(no log)"
                delay(1000)
            }
        }
        if (!File(netDir, "tinc.conf").isFile) {
            OnboardingScreen(onScan = ::notYet, onLink = ::notYet)
            return
        }
        if (advanced) {
            BackHandler { advanced = false }
            AdvancedScreen(log, onBack = { advanced = false })
            return
        }
        // Devices and inviter will come from invitation metadata. Not wired yet.
        val state = HomeState(network = "tincr", link = link, devices = emptyList(), inviter = "your admin")
        MainScreen(
            state, tab, onTab = { tab = it },
            onToggle = { if (TincrVpnService.running) stop() else prepareAndStart() },
            onHelpReport = { sendHelpReport(log) },
            onSettings = { advanced = true },
        )
    }

    private fun notYet() {
        Toast.makeText(this, "Joining is not implemented yet", Toast.LENGTH_SHORT).show()
    }

    private fun sendHelpReport(log: String) {
        val send = Intent(Intent.ACTION_SEND).setType("text/plain")
            .putExtra(Intent.EXTRA_SUBJECT, "tincr help report")
            .putExtra(Intent.EXTRA_TEXT, log)
        startActivity(Intent.createChooser(send, "Send help report"))
    }

    private fun stop() {
        startService(Intent(this, TincrVpnService::class.java).setAction(TincrVpnService.ACTION_STOP))
    }

    private fun prepareAndStart() {
        val ask = VpnService.prepare(this)
        if (ask != null) consent.launch(ask) else startVpn()
    }

    private fun startVpn() {
        startForegroundService(Intent(this, TincrVpnService::class.java))
    }
}
