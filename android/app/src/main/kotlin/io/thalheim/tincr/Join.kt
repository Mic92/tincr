package io.thalheim.tincr

import android.content.Context
import java.io.File
import java.net.InetAddress

class JoinError(message: String) : Exception(message)

// Accepts an invitation by exec'ing libtinc.so, then derives vpn.conf
// from the Ifconfig/Route lines the inviter put into the invitation.
object Join {
    private val SLUG = Regex("[0-9A-Za-z_-]{48}")
    private val IP_LITERAL = Regex("[0-9.]+|[0-9a-fA-F:.]*:[0-9a-fA-F:.]*")

    // `tinc://join/HOST[:PORT]/SLUG`, `tinc:HOST/SLUG` or the bare form.
    fun parseLink(s: String): String? {
        val t = s.trim().removePrefix("tinc://join/").removePrefix("tinc://").removePrefix("tinc:")
        val slash = t.lastIndexOf('/')
        return t.takeIf { slash > 0 && SLUG.matches(t.substring(slash + 1)) }
    }

    fun run(context: Context, dir: File, link: String) {
        val url = parseLink(link) ?: throw JoinError("This is not an invitation link.")
        val tinc = File(context.applicationInfo.nativeLibraryDir, "libtinc.so")
        val tmp = File(dir.parentFile, dir.name + ".join")
        tmp.deleteRecursively()
        tmp.mkdirs()
        try {
            val p = ProcessBuilder(tinc.absolutePath, "--batch", "-c", tmp.absolutePath, "join", url)
                .redirectErrorStream(true).start()
            val out = p.inputStream.bufferedReader().readText()
            if (p.waitFor() != 0) throw JoinError(out.lines().lastOrNull { it.isNotBlank() } ?: "join failed")
            finish(tmp)
            dir.deleteRecursively()
            if (!tmp.renameTo(dir)) throw JoinError("cannot move config into place")
        } finally {
            tmp.deleteRecursively()
        }
    }

    private fun finish(dir: File) {
        val config = fromInvitation(dir, File(dir, "invitation-data").readLines())
        File(dir, "vpn.conf").writeText(config.render())
        File(dir, "tinc.conf").appendText("DeviceType = fd\nDevice = @tincr-tun\n")
        // Ports below 1024 are refused for apps.
        File(dir, "hosts/${config.name}").let { f ->
            if (confLines(f.readLines()).none { it.first == "port" }) f.appendText("Port = 0\n")
        }
        File(dir, "tinc-up").delete()
    }

    // First chunk (up to the next `Name =`) is our config, later chunks
    // are peers' host files whose Address must not sit inside a route.
    internal fun fromInvitation(dir: File, data: List<String>): NetworkConfig {
        val kv = confLines(data)
        val own = kv.firstOrNull { it.first == "name" }?.second ?: throw JoinError("invitation has no Name")
        val mine = kv.takeWhile { (k, v) -> k != "name" || v == own }
        val peers = kv.drop(mine.size)
        fun all(k: String) = mine.filter { it.first == k }.map { it.second.substringBefore(' ') }
        val config = NetworkConfig(
            dir,
            network = all("netname").firstOrNull(),
            inviter = all("connectto").firstOrNull(),
            bundleUrl = all("bundleurl").firstOrNull(),
            addresses = all("ifconfig").mapNotNull(CidrAddr::parse),
            routes = all("route").mapNotNull(CidrAddr::parse),
        )
        if (config.addresses.isEmpty()) throw JoinError("The invitation carries no address for this device.")
        val nets = config.routes + config.addresses
        for (a in peers.filter { it.first == "address" }.map { it.second.substringBefore(' ') }) {
            if (!IP_LITERAL.matches(a)) continue
            val hit = nets.firstOrNull { InetAddress.getByName(a) in it } ?: continue
            throw JoinError("Peer address $a lies inside routed $hit.")
        }
        return config
    }
}
