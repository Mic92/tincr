package io.thalheim.tincr

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import io.thalheim.tincr.ui.AdvancedScreen
import io.thalheim.tincr.ui.Device
import io.thalheim.tincr.ui.HomeState
import io.thalheim.tincr.ui.JoinScreen
import io.thalheim.tincr.ui.Link
import io.thalheim.tincr.ui.MainScreen
import io.thalheim.tincr.ui.OnboardingScreen
import io.thalheim.tincr.ui.Tab
import io.thalheim.tincr.ui.TincrTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import androidx.compose.runtime.rememberCoroutineScope
import java.io.File

class MainActivity : ComponentActivity() {
    private val netDir get() = File(filesDir, "networks/default")
    private val consent = registerForActivityResult(StartActivityForResult()) {
        if (it.resultCode == RESULT_OK) startVpn() else Vpn.problem = Problems.consentMissing()
    }

    // Non-null shows the join screen. Set by deep link, QR scan or the button.
    private var joinLink by mutableStateOf<String?>(null)
    private val scan = registerForActivityResult(ScanContract()) { r ->
        r.contents?.let { joinLink = it }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        joinLink = intent.data?.takeIf { it.scheme == "tinc" }?.toString()
        setContent { TincrTheme { App() } }
        // adb/test entry. Consent must be pre-granted via appops.
        if (intent.getBooleanExtra("autostart", false)) {
            prepareAndStart()
        }
    }

    // People open the app when something is off, so refresh hosts/ now.
    override fun onResume() {
        super.onResume()
        BundleJob.kick(this, NetworkConfig.load(netDir))
    }

    @Composable
    private fun App() {
        var tab by remember { mutableStateOf(Tab.Home) }
        var advanced by remember { mutableStateOf(false) }
        var log by remember { mutableStateOf("") }
        var state by remember { mutableStateOf(homeState(emptyMap(), Vpn.phase)) }
        var joined by remember { mutableStateOf(File(netDir, "tinc.conf").isFile) }
        var joinBusy by remember { mutableStateOf(false) }
        var joinError by remember { mutableStateOf<String?>(null) }
        val scope = rememberCoroutineScope()
        LaunchedEffect(Unit) {
            while (true) {
                val phase = Vpn.phase
                val (nodes, tail) = withContext(Dispatchers.IO) {
                    (if (phase == Phase.Running) TincCtl(netDir).nodes() else emptyMap()) to
                        TincdRunner.logTail(netDir, 200).ifEmpty { "(no log)" }
                }
                state = homeState(nodes, phase)
                log = tail
                delay(1000)
            }
        }
        val link = joinLink
        if (!joined && link != null) {
            BackHandler(!joinBusy) { joinLink = null }
            JoinScreen(
                link, { joinLink = it; joinError = null }, joinBusy, joinError,
                onJoin = {
                    joinBusy = true
                    scope.launch {
                        joinError = withContext(Dispatchers.IO) {
                            runCatching { Join.run(this@MainActivity, netDir, link) }.exceptionOrNull()?.message
                        }
                        joinBusy = false
                        joined = joinError == null
                    }
                },
                onBack = { joinLink = null },
            )
            return
        }
        if (!joined) {
            OnboardingScreen(onScan = ::scanQr, onLink = { joinLink = "" })
            return
        }
        if (advanced) {
            BackHandler { advanced = false }
            AdvancedScreen(log, onBack = { advanced = false })
            return
        }
        MainScreen(
            state, tab, onTab = { tab = it },
            onToggle = { if (Vpn.phase == Phase.Off) prepareAndStart() else stop() },
            onHelpReport = { sendHelpReport(state, log) },
            onSettings = { advanced = true },
        )
    }

    // Connected only once a peer is reachable, not merely when tincd is up.
    private fun homeState(nodes: Map<String, Boolean>, phase: Phase): HomeState {
        val cfg = NetworkConfig.load(netDir)
        val self = cfg.name
        val devices = cfg.hosts.map { Device(it, "", online = nodes[it] == true, self = it == self) }
        val anyPeer = devices.any { it.online && !it.self }
        return HomeState(
            network = cfg.network ?: "tincr",
            link = when {
                phase == Phase.Off || phase == Phase.Stopping -> Link.Off
                anyPeer -> Link.Connected
                else -> Link.Connecting
            },
            devices = devices,
            inviter = cfg.inviter ?: "the person who invited you",
            notice = Vpn.problem ?: BundleJob.lastProblem,
        )
    }

    private fun scanQr() {
        scan.launch(
            ScanOptions().setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                .setPrompt("Scan the invitation code").setBeepEnabled(false).setOrientationLocked(false),
        )
    }

    private fun sendHelpReport(state: HomeState, log: String) {
        val cfg = NetworkConfig.load(netDir)
        val text = buildString {
            append("tincr ").append(runCatching { packageManager.getPackageInfo(packageName, 0).versionName }.getOrNull()).append('\n')
            append("Android ").append(android.os.Build.VERSION.RELEASE).append(" (").append(android.os.Build.MODEL).append(")\n")
            append("node ").append(cfg.name).append(" network ").append(cfg.network).append(" via ").append(cfg.inviter).append('\n')
            append("state ").append(Vpn.phase).append(", ").append(state.onlineCount).append('/').append(state.devices.size).append(" reachable\n")
            state.notice?.let { append("\nProblem: ").append(it.title).append('\n').append(it.detail).append('\n') }
            append("\n--- tincd.log (last 200 lines) ---\n").append(log)
        }
        val send = Intent(Intent.ACTION_SEND).setType("text/plain")
            .putExtra(Intent.EXTRA_SUBJECT, "tincr help report from ${cfg.name}")
            .putExtra(Intent.EXTRA_TEXT, text)
        startActivity(Intent.createChooser(send, "Send help report"))
    }

    private fun stop() {
        startService(Intent(this, TincrVpnService::class.java).setAction(TincrVpnService.ACTION_STOP))
    }

    private fun prepareAndStart() {
        val ask = try {
            VpnService.prepare(this)
        } catch (e: IllegalStateException) {
            Vpn.problem = Problems.consentMissing().copy(detail = "prepare: ${e.message}")
            return
        }
        if (ask != null) consent.launch(ask) else startVpn()
    }

    private fun startVpn() {
        startForegroundService(Intent(this, TincrVpnService::class.java))
    }
}
