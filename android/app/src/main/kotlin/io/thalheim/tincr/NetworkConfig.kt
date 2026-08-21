package io.thalheim.tincr

import java.io.File

data class CidrAddr(val address: String, val prefix: Int)

/// Per-network app-side settings, next to the tinc config tree in
/// `filesDir/networks/<name>/`. Format: `key value` lines in
/// `vpn.conf` (address/route/dns/domain/mtu). The tinc side
/// (tinc.conf, hosts/) lives in the same dir.
data class NetworkConfig(
    val dir: File,
    val addresses: List<CidrAddr>,
    val routes: List<CidrAddr>,
    val dnsServers: List<String>,
    val searchDomains: List<String>,
    val mtu: Int,
) {
    companion object {
        fun load(dir: File): NetworkConfig {
            val addresses = mutableListOf<CidrAddr>()
            val routes = mutableListOf<CidrAddr>()
            val dns = mutableListOf<String>()
            val domains = mutableListOf<String>()
            var mtu = 1400

            val f = File(dir, "vpn.conf")
            if (f.isFile) {
                f.forEachLine { line ->
                    val t = line.trim()
                    if (t.isEmpty() || t.startsWith("#")) return@forEachLine
                    val (key, value) = t.split(Regex("\\s+"), limit = 2)
                        .takeIf { it.size == 2 } ?: return@forEachLine
                    when (key.lowercase()) {
                        "address" -> cidr(value)?.let { addresses.add(it) }
                        "route" -> cidr(value)?.let { routes.add(it) }
                        "dns" -> dns.add(value)
                        "domain" -> domains.add(value)
                        "mtu" -> value.toIntOrNull()?.let { mtu = it }
                    }
                }
            }
            return NetworkConfig(dir, addresses, routes, dns, domains, mtu)
        }

        private fun cidr(s: String): CidrAddr? {
            val parts = s.split("/")
            if (parts.size != 2) return null
            val prefix = parts[1].toIntOrNull() ?: return null
            return CidrAddr(parts[0], prefix)
        }
    }
}
