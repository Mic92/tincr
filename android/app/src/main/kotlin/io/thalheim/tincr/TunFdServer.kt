package io.thalheim.tincr

import android.net.LocalServerSocket
import java.io.FileDescriptor

// Sends the tun fd via SCM_RIGHTS to tincd (Device = @NAME).
class TunFdServer(name: String, private val fd: FileDescriptor) {
    private val server = LocalServerSocket(name)

    fun serveOnce() {
        try {
            server.accept().use {
                it.setFileDescriptorsForSend(arrayOf(fd))
                it.outputStream.write(1)
                it.outputStream.flush()
            }
        } finally {
            server.close()
        }
    }
}
