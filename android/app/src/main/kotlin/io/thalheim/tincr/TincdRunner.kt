package io.thalheim.tincr

import android.content.Context
import android.util.Log
import java.io.File
import java.util.concurrent.TimeUnit

// Runs libtincd.so from nativeLibraryDir against a config dir.
class TincdRunner(context: Context, private val config: NetworkConfig) {
    private val binary = File(context.applicationInfo.nativeLibraryDir, "libtincd.so")
    private val confDir = config.dir
    private var process: Process? = null

    fun start() {
        reapOrphan()
        val p = ProcessBuilder(
            binary.absolutePath,
            "--config", confDir.absolutePath,
            "--pidfile", File(confDir, "tincd.pid").absolutePath,
            "--logfile", File(confDir, "tincd.log").absolutePath,
            "--debug", "5",
        ).redirectErrorStream(true).start()
        process = p
        Thread {
            p.inputStream.bufferedReader().forEachLine { Log.i("tincd", it) }
        }.apply { isDaemon = true }.start()
    }

    fun stop() {
        TincCtl(confDir).request(TincCtl.REQ_STOP)
        process?.let {
            if (!it.waitFor(5, TimeUnit.SECONDS)) {
                it.destroy()
                if (!it.waitFor(2, TimeUnit.SECONDS)) it.destroyForcibly()
            }
        }
        process = null
    }

    // Exec'd daemons outlive the app process. Stop leftovers or
    // the port bind fails.
    private fun reapOrphan() {
        val pid = File(confDir, "tincd.pid").takeIf { it.isFile }
            ?.readText()?.split(Regex("\\s+"))?.firstOrNull()?.toIntOrNull()
            ?: return
        if (!File("/proc/$pid").isDirectory) return
        Log.i("tincr", "stopping orphaned tincd (pid $pid)")
        TincCtl(confDir).request(TincCtl.REQ_STOP)
        for (i in 0 until 50) {
            if (!File("/proc/$pid").isDirectory) return
            Thread.sleep(100)
        }
        android.os.Process.sendSignal(pid, 9)
    }
}
