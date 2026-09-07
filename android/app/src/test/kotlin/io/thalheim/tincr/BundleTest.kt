package io.thalheim.tincr

import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.file.Files
import java.util.zip.GZIPOutputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class BundleTest {
    private fun tgz(vararg files: Pair<String, String>): ByteArray {
        val out = ByteArrayOutputStream()
        GZIPOutputStream(out).use { gz ->
            for ((name, body) in files) {
                val hdr = ByteArray(512)
                name.toByteArray().copyInto(hdr, 0)
                "0000644".toByteArray().copyInto(hdr, 100)
                String.format("%011o", body.length).toByteArray().copyInto(hdr, 124)
                hdr[156] = '0'.code.toByte()
                "ustar".toByteArray().copyInto(hdr, 257)
                "        ".toByteArray().copyInto(hdr, 148)
                String.format("%06o", hdr.sumOf { it.toInt() and 0xFF }).toByteArray().copyInto(hdr, 148)
                gz.write(hdr)
                gz.write(body.toByteArray())
                gz.write(ByteArray((512 - body.length % 512) % 512))
            }
            gz.write(ByteArray(1024))
        }
        return out.toByteArray()
    }

    private fun netDir(): File {
        val dir = Files.createTempDirectory("bundle").toFile()
        File(dir, "tinc.conf").writeText("Name = phone\n")
        File(dir, "hosts").mkdirs()
        File(dir, "hosts/phone").writeText("Ed25519PublicKey = mine\n")
        File(dir, "hosts/stale").writeText("gone after update\n")
        return dir
    }

    @Test
    fun replacesHostsButKeepsOwn() {
        val dir = netDir()
        val n = Bundle.install(
            NetworkConfig.load(dir),
            tgz("hosts/gate" to "Address = 1.2.3.4\n", "./eve" to "Address = 5.6.7.8\n", "README.md" to "x").inputStream(),
        )
        assertEquals(2, n)
        assertEquals(listOf("eve", "gate", "phone"), File(dir, "hosts").list()!!.sorted())
        assertEquals("Ed25519PublicKey = mine\n", File(dir, "hosts/phone").readText())
        assertEquals(false, File(dir, "hosts.new").exists() || File(dir, "hosts.old").exists())
    }

    @Test
    fun bundleOverridesStaleOwnEntry() {
        val dir = netDir()
        Bundle.install(NetworkConfig.load(dir), tgz("phone" to "Ed25519PublicKey = registry\n").inputStream())
        // Local copy wins so a pending key change is not reverted.
        assertEquals("Ed25519PublicKey = mine\n", File(dir, "hosts/phone").readText())
    }

    @Test
    fun emptyBundleKeepsHosts() {
        val dir = netDir()
        assertThrows(java.io.IOException::class.java) {
            Bundle.install(NetworkConfig.load(dir), tgz("README.md" to "nothing").inputStream())
        }
        assertEquals(listOf("phone", "stale"), File(dir, "hosts").list()!!.sorted())
    }
}
