package io.thalheim.tincr

import android.content.Context
import android.util.Log
import java.io.File

// Runs libtincd.so from nativeLibraryDir against a config dir.
class TincdRunner(context: Context, private val config: NetworkConfig) {
    private val binary = File(context.applicationInfo.nativeLibraryDir, "libtincd.so")
    private val confDir = config.dir
    private var process: Process? = null

    fun start() {
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
        process?.let {
            it.destroy()
            if (!it.waitFor(5, java.util.concurrent.TimeUnit.SECONDS)) {
                it.destroyForcibly()
            }
        }
        process = null
    }
}
