package io.thalheim.tincr

import android.net.LocalServerSocket
import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.util.Log
import java.io.Closeable
import java.io.FileDescriptor
import java.io.IOException
import kotlin.concurrent.thread

// Hands the tun fd via SCM_RIGHTS to each tincd that connects to @NAME.
class TunFdServer(private val name: String, private val fd: FileDescriptor) : Closeable {
    private val server = LocalServerSocket(name)

    @Volatile
    private var closed = false

    init {
        thread(name = "tincr-tunfd", isDaemon = true) {
            while (!closed) {
                try {
                    server.accept().use {
                        if (closed) return@use
                        it.setFileDescriptorsForSend(arrayOf(fd))
                        it.outputStream.write(1)
                        it.outputStream.flush()
                    }
                } catch (e: IOException) {
                    if (!closed) Log.w("tincr", "tun fd handover: ${e.message}")
                }
            }
        }
    }

    // close() alone does not wake accept().
    override fun close() {
        if (closed) return
        closed = true
        runCatching { server.close() }
        runCatching { LocalSocket().use { it.connect(LocalSocketAddress(name)) } }
    }
}
