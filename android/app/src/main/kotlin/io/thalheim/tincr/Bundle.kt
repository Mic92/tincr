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
    private val NAME = Regex("[A-Za-z0-9_]+")

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
                else -> throw java.io.IOException("bundle fetch: HTTP $code")
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
        untar(GZIPInputStream(tgz)) { name, body ->
            if (NAME.matches(name)) {
                File(fresh, name).writeBytes(body)
                n++
            }
        }
        if (n == 0) {
            fresh.deleteRecursively()
            throw java.io.IOException("bundle has no host files")
        }
        val hosts = File(dir, "hosts")
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

    // ustar reader, regular files only, basename of each entry.
    private fun untar(input: InputStream, entry: (String, ByteArray) -> Unit) {
        val din = DataInputStream(input)
        val hdr = ByteArray(512)
        while (true) {
            din.readFully(hdr)
            if (hdr[0] == 0.toByte()) return
            val name = String(hdr, 0, 100).substringBefore('\u0000').substringAfterLast('/')
            val size = String(hdr, 124, 12).trim('\u0000', ' ').ifEmpty { "0" }.toLong(8)
            val type = hdr[156].toInt().toChar()
            val body = ByteArray(size.toInt())
            din.readFully(body)
            din.skipBytes(((512 - size % 512) % 512).toInt())
            if ((type == '0' || type == '\u0000') && name.isNotEmpty()) entry(name, body)
        }
    }
}
