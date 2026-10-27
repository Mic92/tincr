package io.thalheim.tincr

import android.net.LocalServerSocket
import java.io.Closeable
import java.io.FileDescriptor
import java.io.IOException
import kotlin.concurrent.thread

// Sends the tun fd via SCM_RIGHTS to tincd (Device = @NAME).
class TunFdServer(name: String, private val fd: FileDescriptor) : Closeable {
    private val server = LocalServerSocket(name)

    // accept() has no timeout: give up when tincd dies or the deadline passes.
    fun serveOnce(timeoutMs: Long, alive: () -> Boolean): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        val watchdog = thread(name = "tincr-tun-watchdog", isDaemon = true) {
            try {
                while (alive() && System.currentTimeMillis() < deadline) Thread.sleep(100)
                close()
            } catch (_: InterruptedException) {
            }
        }
        return try {
            server.accept().use {
                it.setFileDescriptorsForSend(arrayOf(fd))
                it.outputStream.write(1)
                it.outputStream.flush()
            }
            true
        } catch (_: IOException) {
            false
        } finally {
            watchdog.interrupt()
            close()
        }
    }

    @Synchronized
    override fun close() = server.close()
}
