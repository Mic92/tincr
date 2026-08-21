package io.thalheim.tincr

import android.net.LocalSocket
import android.net.LocalSocketAddress
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader

// Control-socket client: greeting `0 ^COOKIE 0` (two reply
// lines), then `18 <req>` acked with `18 <req> <result>`.
class TincCtl(private val dir: File) {
    companion object {
        const val REQ_STOP = 0
        const val REQ_RETRY = 10
    }

    private fun cookie(): String? =
        File(dir, "tincd.pid").takeIf { it.isFile }
            ?.readText()?.split(Regex("\\s+"))?.getOrNull(1)

    fun request(req: Int): Boolean {
        val cookie = cookie() ?: return false
        return try {
            LocalSocket().use { sock ->
                sock.connect(
                    LocalSocketAddress(
                        File(dir, "tincd.socket").absolutePath,
                        LocalSocketAddress.Namespace.FILESYSTEM,
                    )
                )
                val r = BufferedReader(InputStreamReader(sock.inputStream))
                sock.outputStream.write("0 ^$cookie 0\n".toByteArray())
                r.readLine() ?: return false
                r.readLine() ?: return false
                sock.outputStream.write("18 $req\n".toByteArray())
                val ack = r.readLine() ?: return false
                ack.startsWith("18 $req 0")
            }
        } catch (e: java.io.IOException) {
            false
        }
    }
}
