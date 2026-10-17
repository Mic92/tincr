package io.thalheim.tincr

import java.io.File

// App-side settings from vpn.conf next to the tinc config tree.
data class NetworkConfig(
    val dir: File,
    val network: String? = null,
    val inviter: String? = null,
    val bundleUrl: String? = null,
    val addresses: List<CidrAddr> = emptyList(),
    val routes: List<CidrAddr> = emptyList(),
    val dnsServers: List<String> = emptyList(),
    val searchDomains: List<String> = emptyList(),
    val mtu: Int = 1400,
) {
    val name: String?
        get() = File(dir, "tinc.conf").takeIf { it.isFile }
            ?.let { confLines(it.readLines()) }?.firstOrNull { it.first == "name" }?.second
    val hosts: List<String>
        get() = File(dir, "hosts").list()?.sorted().orEmpty()

    fun render() = buildString {
        network?.let { append("network $it\n") }
        inviter?.let { append("inviter $it\n") }
        bundleUrl?.let { append("bundle $it\n") }
        addresses.forEach { append("address $it\n") }
        routes.forEach { append("route $it\n") }
        dnsServers.forEach { append("dns $it\n") }
        searchDomains.forEach { append("domain $it\n") }
        if (mtu != 1400) append("mtu $mtu\n")
    }

    companion object {
        fun load(dir: File): NetworkConfig {
            val f = File(dir, "vpn.conf").takeIf { it.isFile } ?: return NetworkConfig(dir)
            val kv = confLines(f.readLines())
            fun all(k: String) = kv.filter { it.first == k }.map { it.second }
            return NetworkConfig(
                dir,
                network = all("network").lastOrNull(),
                inviter = all("inviter").lastOrNull(),
                bundleUrl = all("bundle").lastOrNull(),
                addresses = all("address").mapNotNull(CidrAddr::parse),
                routes = all("route").mapNotNull(CidrAddr::parse),
                dnsServers = all("dns"),
                searchDomains = all("domain"),
                mtu = all("mtu").lastOrNull()?.toIntOrNull() ?: 1400,
            )
        }
    }
}
