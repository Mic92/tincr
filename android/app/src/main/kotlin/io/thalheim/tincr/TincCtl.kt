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
        const val REQ_RELOAD = 1
        const val REQ_DUMP_NODES = 3
        const val REQ_RETRY = 10
    }

    private fun cookie(): String? =
        File(dir, "tincd.pid").takeIf { it.isFile }
            ?.readText()?.split(Regex("\\s+"))?.getOrNull(1)

    fun request(req: Int): Boolean = converse(req)?.let { it.lastOrNull()?.startsWith("18 $req 0") } ?: false

    // Node name -> reachable, from `dump nodes` (status bit 4).
    fun nodes(): Map<String, Boolean> = converse(REQ_DUMP_NODES).orEmpty()
        .map { it.split(' ') }
        .filter { it.size > 12 }
        .associate { it[2] to ((it[12].toIntOrNull(16) ?: 0) and 0x10 != 0) }

    // Lines up to and including the `18 <req> ...` terminator.
    private fun converse(req: Int): List<String>? {
        val cookie = cookie() ?: return null
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
                r.readLine() ?: return null
                r.readLine() ?: return null
                sock.outputStream.write("18 $req\n".toByteArray())
                // Dump rows have many fields, the final `18 <req> <result>` three.
                val out = mutableListOf<String>()
                do {
                    out.add(r.readLine() ?: return null)
                } while (out.last().split(' ').size > 3)
                out
            }
        } catch (e: java.io.IOException) {
            null
        }
    }
}
