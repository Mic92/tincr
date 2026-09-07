package io.thalheim.tincr

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

class JoinTest {
    private val slug = "A".repeat(48)

    @Test
    fun parsesLinks() {
        assertEquals("h:1/$slug", Join.parseLink("tinc://join/h:1/$slug"))
        assertEquals("h/$slug", Join.parseLink(" h/$slug\n"))
        assertEquals("[::1]:655/$slug", Join.parseLink("tinc:[::1]:655/$slug"))
        assertNull(Join.parseLink("h/short"))
        assertNull(Join.parseLink("https://example.com/"))
    }

    @Test
    fun vpnConfFromInvitation() {
        val data = """
            Name = phone
            NetName = mesh
            ConnectTo = gate
            Ifconfig = 10.243.42.42/16
            Route = 10.243.0.0/16
            Route = 42::/16
            #-------------------------------------#
            Name = gate
            Address = 192.0.2.1 655
            Subnet = 10.243.0.1
        """.trimIndent().lines()
        assertEquals(
            "network mesh\ninviter gate\naddress 10.243.42.42/16\nroute 10.243.0.0/16\nroute 42::/16\n",
            Join.vpnConf(data),
        )
    }

    @Test
    fun peerAddressInsideRouteIsRefused() {
        val data = """
            Name = phone
            Ifconfig = 10.243.42.42/16
            Name = gate
            Address = 10.243.0.1
        """.trimIndent().lines()
        val e = assertThrows(JoinError::class.java) { Join.vpnConf(data) }
        assertEquals("Peer address 10.243.0.1 lies inside routed 10.243.0.0/16.", e.message)
    }

    @Test
    fun missingIfconfigIsRefused() {
        assertThrows(JoinError::class.java) { Join.vpnConf(listOf("Name = phone")) }
    }
}
