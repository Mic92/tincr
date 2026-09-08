package io.thalheim.tincr

import java.net.InetAddress

data class CidrAddr(val address: String, val prefix: Int) {
    override fun toString() = "$address/$prefix"

    operator fun contains(ip: InetAddress): Boolean {
        val n = InetAddress.getByName(address).address
        val a = ip.address
        if (n.size != a.size) return false
        for (i in n.indices) {
            val bits = (prefix - i * 8).coerceIn(0, 8)
            val mask = (0xFF shl (8 - bits)) and 0xFF
            if ((n[i].toInt() and mask) != (a[i].toInt() and mask)) return false
        }
        return true
    }

    companion object {
        fun parse(s: String): CidrAddr? {
            val (a, p) = s.split('/').takeIf { it.size == 2 } ?: return null
            return CidrAddr(a, p.toIntOrNull() ?: return null)
        }
    }
}

// `Key = value` or `key value`, comments and blanks skipped, key lowercased.
fun confLines(lines: List<String>): List<Pair<String, String>> = lines.mapNotNull { line ->
    val t = line.trim()
    if (t.isEmpty() || t.startsWith("#")) return@mapNotNull null
    val i = t.indexOfFirst { it == '=' || it.isWhitespace() }.takeIf { it > 0 } ?: return@mapNotNull null
    t.substring(0, i).lowercase() to t.substring(i).trimStart().removePrefix("=").trim()
}
