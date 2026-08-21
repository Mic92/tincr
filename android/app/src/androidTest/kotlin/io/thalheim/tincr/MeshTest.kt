package io.thalheim.tincr

import android.content.Context
import android.content.Intent
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.net.NetworkInterface
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

// Two-node mesh inside the emulator: the app's own libtincd.so
// also runs the peer ("gate", dummy device) on 127.0.0.1.
@RunWith(AndroidJUnit4::class)
class MeshTest {
    private val ctx: Context =
        InstrumentationRegistry.getInstrumentation().targetContext
    private var gate: TincdRunner? = null

    private fun copyAssets(from: String, to: File) {
        val assets = InstrumentationRegistry.getInstrumentation().context.assets
        for (name in assets.list(from).orEmpty()) {
            val src = "$from/$name"
            if (assets.list(src).orEmpty().isNotEmpty()) {
                copyAssets(src, File(to, name))
            } else {
                File(to, name).apply { parentFile!!.mkdirs() }
                    .outputStream().use { assets.open(src).copyTo(it) }
            }
        }
    }

    private fun shell(cmd: String): String {
        val pfd = InstrumentationRegistry.getInstrumentation().uiAutomation
            .executeShellCommand(cmd)
        return android.os.ParcelFileDescriptor.AutoCloseInputStream(pfd)
            .use { String(it.readBytes()) }
    }

    private fun poll(timeoutMs: Long, what: String, cond: () -> Boolean) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (cond()) return
            Thread.sleep(500)
        }
        val logs = listOf("networks/default/tincd.log", "gate/tincd.log")
            .joinToString("\n") { rel ->
                val f = File(ctx.filesDir, rel)
                "== $rel ==\n" + if (f.isFile) {
                    f.readLines().takeLast(15).joinToString("\n")
                } else {
                    "(missing)"
                }
            }
        val logcat = shell("logcat -d -s tincr tincr:I AndroidRuntime:E")
            .lines().takeLast(20).joinToString("\n")
        val appops = shell("appops get ${ctx.packageName} ACTIVATE_VPN")
        val prepared = android.net.VpnService.prepare(ctx) == null
        throw AssertionError(
            "timeout: $what\n$logs\n== logcat ==\n$logcat\n" +
                "appops: $appops prepared: $prepared"
        )
    }

    @Test
    fun meshComesUp() {
        val phoneDir = File(ctx.filesDir, "networks/default")
        val gateDir = File(ctx.filesDir, "gate")
        phoneDir.deleteRecursively()
        gateDir.deleteRecursively()
        copyAssets("mesh/phone", phoneDir)
        copyAssets("mesh/gate", gateDir)

        gate = TincdRunner(ctx, NetworkConfig.load(gateDir)).also { it.start() }
        shell("appops set ${ctx.packageName} ACTIVATE_VPN allow")
        poll(10_000, "VPN consent") { android.net.VpnService.prepare(ctx) == null }
        ctx.startForegroundService(Intent(ctx, TincrVpnService::class.java))

        val phoneLog = File(phoneDir, "tincd.log")
        val gateLog = File(gateDir, "tincd.log")
        fun log(f: File) = if (f.isFile) f.readText() else ""

        poll(30_000, "meta connection") {
            log(phoneLog).contains("Node gate became reachable") &&
                log(gateLog).contains("Node phone became reachable")
        }
        poll(30_000, "UDP path") {
            log(phoneLog).contains("UDP address of gate confirmed")
        }
        poll(30_000, "tun device") {
            NetworkInterface.getNetworkInterfaces().asSequence().any { ni ->
                ni.inetAddresses.asSequence()
                    .any { it.hostAddress == "10.243.42.42" }
            }
        }
        assertTrue(log(phoneLog).contains("Ready"))
    }

    @After
    fun tearDown() {
        ctx.startService(
            Intent(ctx, TincrVpnService::class.java)
                .setAction(TincrVpnService.ACTION_STOP)
        )
        gate?.stop()
    }
}
