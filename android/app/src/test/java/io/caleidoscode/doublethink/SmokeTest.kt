package io.caleidoscode.doublethink

import org.junit.Assert.assertNotNull
import org.junit.Test

/**
 * Proves the unit-test source set can read classpath resources from
 * app/src/test/resources/. The real crypto parity test depends on vectors.json
 * being on the classpath, so guard that wiring here.
 */
class SmokeTest {
    @Test
    fun vectorsResourceIsOnClasspath() {
        val stream = javaClass.getResourceAsStream("/vectors.json")
        assertNotNull("vectors.json must be on the test classpath", stream)
        stream?.close()
    }
}
