package io.thalheim.tincr

import android.content.Context
import java.io.File
import java.net.InetAddress

class JoinError(message: String) : Exception(message)

// Accepts an invitation by exec'ing libtinc.so, then derives vpn.conf
// from the Ifconfig/Route lines the inviter put into the invitation.
object Join {
    private val SLUG = Regex("[0-9A-Za-z_-]{48}")

    // `tinc://join/HOST[:PORT]/SLUG`, `tinc:HOST/SLUG` or the bare form.
    fun parseLink(s: String): String? {
        val t = s.trim()
            .removePrefix("tinc://join/")
            .removePrefix("tinc://")
            .removePrefix("tinc:")
        val slash = t.lastIndexOf('/')
        if (slash <= 0 || !SLUG.matches(t.substring(slash + 1))) return null
        return t
    }

    fun run(context: Context, dir: File, link: String) {
        val url = parseLink(link) ?: throw JoinError("This is not an invitation link.")
        val tinc = File(context.applicationInfo.nativeLibraryDir, "libtinc.so")
        val tmp = File(dir.parentFile, dir.name + ".join").apply {
            deleteRecursively()
            mkdirs()
        }
        val p = ProcessBuilder(tinc.absolutePath, "--batch", "-c", tmp.absolutePath, "join", url)
            .redirectErrorStream(true).start()
        val out = p.inputStream.bufferedReader().readText()
        if (p.waitFor() != 0) {
            tmp.deleteRecursively()
            throw JoinError(out.lines().lastOrNull { it.isNotBlank() } ?: "join failed")
        }
        try {
            finish(tmp)
        } catch (e: Exception) {
            tmp.deleteRecursively()
            throw e
        }
        dir.deleteRecursively()
        if (!tmp.renameTo(dir)) throw JoinError("cannot move config into place")
    }

    internal fun finish(dir: File) {
        val data = File(dir, "invitation-data").readLines()
        val vpn = vpnConf(data)
        File(dir, "vpn.conf").writeText(vpn)
        File(dir, "tinc.conf").appendText("DeviceType = fd\nDevice = @tincr-tun\n")
        val own = ownName(data)
        // Ports below 1024 are refused for apps.
        File(dir, "hosts/$own").let { f ->
            if (f.readLines().none { key(it) == "port" }) f.appendText("Port = 0\n")
        }
        File(dir, "tinc-up").delete()
    }

    private fun key(line: String) = line.substringBefore('=').trim().lowercase()
    private fun value(line: String) = line.substringAfter('=', "").trim()

    private fun ownName(data: List<String>) =
        data.firstOrNull { key(it) == "name" }?.let(::value) ?: throw JoinError("invitation has no Name")

    // First chunk (up to the next `Name =`) is our config, later chunks
    // are peers' host files whose Address must not sit inside a route.
    internal fun vpnConf(data: List<String>): String {
        val own = ownName(data)
        var network: String? = null
        var inviter: String? = null
        var bundle: String? = null
        val addrs = mutableListOf<CidrAddr>()
        val routes = mutableListOf<CidrAddr>()
        val peerAddrs = mutableListOf<String>()
        var chunk = 0
        for (line in data) {
            if (line.startsWith("#")) continue
            val k = key(line)
            val v = value(line)
            if (k == "name" && v != own) chunk++
            when {
                chunk == 0 && k == "netname" -> network = v
                chunk == 0 && k == "bundleurl" -> bundle = v
                chunk == 0 && k == "connectto" && inviter == null -> inviter = v
                chunk == 0 && k == "ifconfig" -> cidr(v)?.let(addrs::add)
                chunk == 0 && k == "route" -> cidr(v.substringBefore(' '))?.let(routes::add)
                chunk > 0 && k == "address" -> peerAddrs.add(v.substringBefore(' '))
            }
        }
        if (addrs.isEmpty()) throw JoinError("The invitation carries no address for this device.")
        for (a in peerAddrs) {
            val ip = runCatching { literal(a) }.getOrNull() ?: continue
            val hit = (routes + addrs.map { subnet(it) }).firstOrNull { contains(it, ip) }
            if (hit != null) throw JoinError("Peer address $a lies inside routed ${hit.address}/${hit.prefix}.")
        }
        return buildString {
            network?.let { append("network $it\n") }
            inviter?.let { append("inviter $it\n") }
            bundle?.let { append("bundle $it\n") }
            addrs.forEach { append("address ${it.address}/${it.prefix}\n") }
            routes.forEach { append("route ${it.address}/${it.prefix}\n") }
        }
    }

    private fun cidr(s: String): CidrAddr? {
        val (a, p) = s.split('/').takeIf { it.size == 2 } ?: return null
        return CidrAddr(a, p.toIntOrNull() ?: return null)
    }

    // Only IP literals. Hostnames are not resolved here.
    private fun literal(s: String): InetAddress? =
        if (s.any { it.isLetter() && it !in "abcdefABCDEF" } || (':' !in s && s.count { it == '.' } != 3)) null
        else InetAddress.getByName(s)

    private fun subnet(c: CidrAddr): CidrAddr {
        val b = InetAddress.getByName(c.address).address
        for (i in b.indices) {
            val keep = (c.prefix - i * 8).coerceIn(0, 8)
            b[i] = (b[i].toInt() and (0xFF shl (8 - keep) and 0xFF)).toByte()
        }
        return CidrAddr(InetAddress.getByAddress(b).hostAddress!!, c.prefix)
    }

    private fun contains(net: CidrAddr, ip: InetAddress): Boolean {
        val n = InetAddress.getByName(net.address).address
        val a = ip.address
        if (n.size != a.size) return false
        var bits = net.prefix
        for (i in n.indices) {
            if (bits <= 0) return true
            val mask = if (bits >= 8) 0xFF else (0xFF shl (8 - bits)) and 0xFF
            if ((n[i].toInt() and mask) != (a[i].toInt() and mask)) return false
            bits -= 8
        }
        return true
    }
}
