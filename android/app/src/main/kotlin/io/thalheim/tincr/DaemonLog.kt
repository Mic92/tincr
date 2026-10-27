package io.thalheim.tincr

import java.io.File
import java.io.RandomAccessFile

// tincd's stderr, rotated to tincd.log.1 past maxBytes.
class DaemonLog(dir: File, private val maxBytes: Long = 512 * 1024) {
    val file = File(dir, "tincd.log")
    private val old = File(dir, "tincd.log.1")

    @Synchronized
    fun append(line: String) {
        if (file.length() >= maxBytes) {
            old.delete()
            file.renameTo(old)
        }
        file.appendText(line + "\n")
    }

    fun tail(maxLines: Int, maxBytes: Int = 32 * 1024): String {
        if (!file.isFile) return "(no log)"
        RandomAccessFile(file, "r").use { f ->
            val start = (f.length() - maxBytes).coerceAtLeast(0)
            val buf = ByteArray((f.length() - start).toInt())
            f.seek(start)
            f.readFully(buf)
            val lines = String(buf).trimEnd().lines().let { if (start > 0) it.drop(1) else it }
            return lines.takeLast(maxLines).joinToString("\n")
        }
    }
}
