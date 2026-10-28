package io.thalheim.tincr

import android.util.Log
import java.io.DataInputStream
import java.io.File
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL
import java.util.zip.GZIPInputStream

// Replaces hosts/ from a tar.gz of host files at `bundle` in vpn.conf.
// Our own host file survives, identity files are never touched.
object Bundle {
    private const val TAG = "tincr"
    // `NAME`, `./NAME` or `hosts/NAME` at most 64 KiB with a host key inside.
    private val ENTRY = Regex("(?:\\./)?(?:hosts/)?([A-Za-z0-9_]+)")
    private val HOST_KEY = Regex("(?im)^\\s*Ed25519PublicKey\\s*=|-----BEGIN RSA PUBLIC KEY-----")
    private const val MAX_ENTRY = 64 * 1024

    // True when hosts/ changed and tincd should reload.
    fun update(config: NetworkConfig): Boolean {
        val url = config.bundleUrl ?: return false
        val etagFile = File(config.dir, "bundle.etag")
        val conn = (URL(url).openConnection() as HttpURLConnection).apply {
            connectTimeout = 15_000
            readTimeout = 30_000
            instanceFollowRedirects = true
            etagFile.takeIf { it.isFile }?.let { setRequestProperty("If-None-Match", it.readText()) }
        }
        try {
            when (val code = conn.responseCode) {
                HttpURLConnection.HTTP_NOT_MODIFIED -> return false
                HttpURLConnection.HTTP_OK -> {}
                HttpURLConnection.HTTP_NOT_FOUND -> throw java.io.IOException("HTTP 404, the bundle URL from the invitation no longer exists")
                else -> throw java.io.IOException("HTTP $code")
            }
            val n = conn.inputStream.use { install(config, it) }
            conn.getHeaderField("ETag")?.let { etagFile.writeText(it) }
            Log.i(TAG, "bundle: $n host files from $url")
            return true
        } finally {
            conn.disconnect()
        }
    }

    internal fun install(config: NetworkConfig, tgz: InputStream): Int {
        val dir = config.dir
        val fresh = File(dir, "hosts.new").apply {
            deleteRecursively()
            mkdirs()
        }
        var n = 0
        untar(GZIPInputStream(tgz)) { path, body ->
            val name = ENTRY.matchEntire(path)?.groupValues?.get(1) ?: return@untar
            if (!HOST_KEY.containsMatchIn(String(body))) return@untar
            File(fresh, name).writeBytes(body)
            n++
        }
        if (n == 0) {
            fresh.deleteRecursively()
            throw java.io.IOException("archive contains no host files")
        }
        // Never lose the ConnectTo peer, or the next start cannot dial anyone.
        val hosts = File(dir, "hosts")
        config.inviter?.let { File(hosts, it).takeIf { f -> f.isFile && !File(fresh, it).exists() }?.copyTo(File(fresh, it)) }
        config.name?.let { own -> File(hosts, own).takeIf { it.isFile }?.copyTo(File(fresh, own), overwrite = true) }
        val old = File(dir, "hosts.old").apply { deleteRecursively() }
        hosts.renameTo(old)
        if (!fresh.renameTo(hosts)) {
            old.renameTo(hosts)
            throw java.io.IOException("cannot move hosts into place")
        }
        old.deleteRecursively()
        return n
    }

    // ustar reader. Hands regular files up to MAX_ENTRY to `entry`, skips
    // everything else (dirs, links, pax headers, big files).
    private fun untar(input: InputStream, entry: (String, ByteArray) -> Unit) {
        val din = DataInputStream(input)
        val hdr = ByteArray(512)
        while (true) {
            din.readFully(hdr)
            if (hdr[0] == 0.toByte()) return
            val path = String(hdr, 0, 100).substringBefore('\u0000')
            val size = String(hdr, 124, 12).trim('\u0000', ' ').ifEmpty { "0" }.toLong(8)
            val type = hdr[156].toInt().toChar()
            val padded = size + (512 - size % 512) % 512
            if ((type == '0' || type == '\u0000') && size <= MAX_ENTRY) {
                val body = ByteArray(size.toInt())
                din.readFully(body)
                din.skipBytes((padded - size).toInt())
                entry(path, body)
            } else {
                var left = padded
                while (left > 0) left -= din.skip(left).also { if (it <= 0) throw java.io.EOFException() }
            }
        }
    }
}
