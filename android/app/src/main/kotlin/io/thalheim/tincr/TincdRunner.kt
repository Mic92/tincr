package io.thalheim.tincr

import android.util.Log
import java.io.File
import java.util.concurrent.TimeUnit

// One libtincd.so process. Not restartable, make a new one.
class TincdRunner(private val binary: File, private val confDir: File) {
    @Volatile
    private var process: Process? = null

    @Volatile
    private var stopping = false

    // onExit runs on a background thread when tincd died on its own.
    fun start(onExit: (Int) -> Unit) {
        check(process == null) { "TincdRunner started twice" }
        reapOrphan(confDir)
        val p = ProcessBuilder(
            binary.absolutePath,
            "--config", confDir.absolutePath,
            "--pidfile", File(confDir, "tincd.pid").absolutePath,
            "--logfile", File(confDir, "tincd.log").absolutePath,
            "--debug", "5",
            "--no-detach",
        ).redirectErrorStream(true).start()
        process = p
        Thread({
            runCatching { p.inputStream.bufferedReader().forEachLine { Log.i("tincd", it) } }
            val rc = runCatching { p.waitFor() }.getOrDefault(-1)
            if (!stopping) onExit(rc)
        }, "tincd-wait").apply { isDaemon = true }.start()
    }

    fun stop() {
        stopping = true
        val p = process ?: return
        TincCtl(confDir).request(TincCtl.REQ_STOP)
        if (!p.waitFor(5, TimeUnit.SECONDS)) {
            p.destroy()
            if (!p.waitFor(2, TimeUnit.SECONDS)) p.destroyForcibly()
        }
    }

    companion object {
        // Exec'd daemons outlive the app process and hold the port.
        fun reapOrphan(confDir: File) {
            val pid = File(confDir, "tincd.pid").takeIf { it.isFile }
                ?.runCatching { readText() }?.getOrNull()
                ?.split(Regex("\\s+"))?.firstOrNull()?.toIntOrNull()
                ?: return
            if (pid <= 1 || pid == android.os.Process.myPid() || !File("/proc/$pid").isDirectory) return
            val cmd = runCatching { File("/proc/$pid/cmdline").readText() }.getOrDefault("")
            if (!cmd.contains("libtincd.so")) return
            Log.i("tincr", "stopping orphaned tincd (pid $pid)")
            TincCtl(confDir).request(TincCtl.REQ_STOP)
            repeat(50) {
                if (!File("/proc/$pid").isDirectory) return
                Thread.sleep(100)
            }
            android.os.Process.sendSignal(pid, 9)
        }

        fun logTail(confDir: File, lines: Int = 20): String =
            File(confDir, "tincd.log").takeIf { it.isFile }
                ?.runCatching { useLines { s -> s.toList().takeLast(lines).joinToString("\n") } }
                ?.getOrNull().orEmpty()
    }
}
