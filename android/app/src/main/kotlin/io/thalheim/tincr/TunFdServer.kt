package io.thalheim.tincr

import android.net.LocalServerSocket
import java.io.FileDescriptor

// Sends the tun fd via SCM_RIGHTS to tincd (Device = @NAME).
class TunFdServer(private val name: String, private val fd: FileDescriptor) {
    fun serveOnce() {
        val server = LocalServerSocket(name)
        try {
            val sock = server.accept()
            sock.use {
                it.setFileDescriptorsForSend(arrayOf(fd))
                it.outputStream.write(1)
                it.outputStream.flush()
            }
        } finally {
            server.close()
        }
    }
}
