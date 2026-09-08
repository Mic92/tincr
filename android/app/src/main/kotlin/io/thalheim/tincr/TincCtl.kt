package io.thalheim.tincr

import android.net.LocalSocket
import android.net.LocalSocketAddress
import java.io.File
import java.io.IOException

// Control socket client. Greeting `0 ^COOKIE 0` (two reply lines), then
// `18 <req>` answered by rows and a final `18 <req> <result>`.
class TincCtl(private val dir: File) {
    companion object {
        const val REQ_STOP = 0
        const val REQ_RELOAD = 1
        const val REQ_DUMP_NODES = 3
        const val REQ_DUMP_CONNECTIONS = 6
        const val REQ_RETRY = 10
        private const val TIMEOUT_MS = 3000
        private const val MAX_ROWS = 100_000
    }

    fun request(req: Int): Boolean = converse(req)?.lastOrNull()?.startsWith("18 $req 0") == true

    // name -> reachable (status bit 4). Empty when the daemon is not up.
    fun nodes(): Map<String, Boolean> = converse(REQ_DUMP_NODES).orEmpty()
        .map { it.split(' ') }
        .filter { it.size > 12 && it[0] == "18" }
        .associate { it[2] to ((it[12].toIntOrNull(16) ?: 0) and 0x10 != 0) }

    // Active meta connections, excluding the control connection itself.
    fun metaConnections(): Int? = converse(REQ_DUMP_CONNECTIONS)
        ?.map { it.split(' ') }
        ?.count { it.size > 5 && it[0] == "18" && it[2] != "<control>" }

    private fun cookie(): String? = File(dir, "tincd.pid").takeIf { it.isFile }
        ?.runCatching { readText() }?.getOrNull()
        ?.split(Regex("\\s+"))?.getOrNull(1)?.takeIf { it.length == 64 }

    private fun converse(req: Int): List<String>? {
        val cookie = cookie() ?: return null
        return try {
            LocalSocket().use { sock ->
                sock.connect(
                    LocalSocketAddress(File(dir, "tincd.socket").absolutePath, LocalSocketAddress.Namespace.FILESYSTEM),
                )
                sock.soTimeout = TIMEOUT_MS
                val r = sock.inputStream.bufferedReader()
                val w = sock.outputStream
                w.write("0 ^$cookie 0\n".toByteArray())
                w.flush()
                r.readLine() ?: return null
                if (r.readLine()?.startsWith("4 ") != true) return null
                w.write("18 $req\n".toByteArray())
                w.flush()
                val out = ArrayList<String>()
                while (out.size < MAX_ROWS) {
                    val line = r.readLine() ?: return null
                    out.add(line)
                    val f = line.split(' ')
                    if (f.size <= 3 && f[0] == "18" && f.getOrNull(1) == "$req") return out
                }
                null
            }
        } catch (_: IOException) {
            null
        }
    }
}
