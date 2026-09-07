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

    private val phoneDir = File(ctx.filesDir, "networks/default")
    private val gateDir = File(ctx.filesDir, "gate")

    private fun freshDirs(withPhone: Boolean) {
        phoneDir.deleteRecursively()
        gateDir.deleteRecursively()
        if (withPhone) copyAssets("mesh/phone", phoneDir)
        copyAssets("mesh/gate", gateDir)
    }

    private fun tinc(dir: File, vararg args: String): String {
        val bin = File(ctx.applicationInfo.nativeLibraryDir, "libtinc.so")
        val p = ProcessBuilder(
            bin.absolutePath, "--batch", "-c", dir.absolutePath,
            "--pidfile", File(dir, "tincd.pid").absolutePath, *args,
        ).redirectErrorStream(true).start()
        val out = p.inputStream.bufferedReader().readText()
        check(p.waitFor() == 0) { "tinc ${args.joinToString(" ")}: $out" }
        return out
    }

    @Test
    fun meshComesUp() {
        freshDirs(withPhone = true)
        gate = TincdRunner(ctx, NetworkConfig.load(gateDir)).also { it.start() }
        bringUpAndCheck()
    }

    // Phone side starts empty and is provisioned purely from an
    // invitation issued by gate, Ifconfig/Route included.
    @Test
    fun joinThenMesh() {
        freshDirs(withPhone = false)
        File(gateDir, "hosts/phone").delete()
        gate = TincdRunner(ctx, NetworkConfig.load(gateDir)).also { it.start() }
        poll(10_000, "gate control socket") { File(gateDir, "tincd.pid").isFile }

        val url = tinc(gateDir, "invite", "phone").lines().first { it.startsWith("127.0.0.1:") }.trim()
        val inv = File(gateDir, "invitations").listFiles()!!.single { it.name != "ed25519_key.priv" }
        // Stands in for an invitation-created hook on the inviter.
        inv.writeText(
            inv.readText().replaceFirst("#--", "Ifconfig = 10.243.42.42/16\nRoute = 10.243.0.0/16\n#--"),
        )

        Join.run(ctx, phoneDir, "tinc://join/$url")

        assertTrue(File(phoneDir, "tinc.conf").readText().contains("ConnectTo = gate"))
        assertTrue(File(phoneDir, "vpn.conf").readText() == "address 10.243.42.42/16\nroute 10.243.0.0/16\n")
        assertTrue(File(gateDir, "hosts/phone").isFile)
        bringUpAndCheck()
    }

    private fun bringUpAndCheck() {
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
