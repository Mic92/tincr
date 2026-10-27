package io.thalheim.tincr

import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DaemonLogTest {
    @Test
    fun rotatesAndTails() {
        val dir = Files.createTempDirectory("daemonlog").toFile()
        val log = DaemonLog(dir, maxBytes = 100)
        repeat(50) { log.append("line $it") }
        assertTrue(log.file.length() <= 100 + 8)
        assertTrue(dir.resolve("tincd.log.1").isFile)
        assertEquals("line 48\nline 49", log.tail(2))
        assertEquals("line 49", DaemonLog(dir).tail(5, maxBytes = 12).lines().last())
        dir.deleteRecursively()
    }
}
