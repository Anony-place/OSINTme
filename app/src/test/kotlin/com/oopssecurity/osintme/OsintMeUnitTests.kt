package com.oopssecurity.osintme

import com.oopssecurity.osintme.data.network.PlatformReconService
import com.oopssecurity.osintme.util.CryptoUtil
import com.oopssecurity.osintme.util.InputClassifier
import com.oopssecurity.osintme.util.InputType
import com.oopssecurity.osintme.util.UrlSanitizer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class OsintMeUnitTests {

    @Test
    fun testSha1HashingForKAnonymity() {
        val input = "password123"
        val expectedHash = "CBFDAC6008F9CAB4083784CBD1874F76618D2A97"
        val actualHash = CryptoUtil.sha1(input).uppercase()

        assertEquals(expectedHash, actualHash)
        assertEquals("CBFDA", actualHash.substring(0, 5))
        assertEquals(40, actualHash.length)
    }

    @Test
    fun testUniversalInputClassifier() {
        assertEquals(InputType.EMAIL, InputClassifier.classify("security.auditor@oopssecurity.com"))
        assertEquals(InputType.IP_ADDRESS, InputClassifier.classify("1.1.1.1"))
        assertEquals(InputType.IP_ADDRESS, InputClassifier.classify("142.250.190.46"))
        assertEquals(InputType.DOMAIN, InputClassifier.classify("oopssecurity.com"))
        assertEquals(InputType.DOMAIN, InputClassifier.classify("crt.sh"))
        assertEquals(InputType.TRACKING_URL, InputClassifier.classify("https://example.org/page?utm_source=fb&utm_medium=cpc&si=abc1234"))
        assertEquals(InputType.USERNAME, InputClassifier.classify("ghostrcr"))
        assertEquals(InputType.USERNAME, InputClassifier.classify("security_lead-99"))
        assertEquals(InputType.GENERIC_KEYWORD, InputClassifier.classify("confidential credentials leak"))
    }

    @Test
    fun testTrackerSanitization() {
        val dirtyUrl = "https://example.com/article?utm_source=newsletter&utm_medium=email&content=cybersecurity&fbclid=AQZ123&si=tracker99"
        val result = UrlSanitizer.sanitize(dirtyUrl)

        assertFalse(result.sanitizedUrl.contains("utm_source"))
        assertFalse(result.sanitizedUrl.contains("utm_medium"))
        assertFalse(result.sanitizedUrl.contains("fbclid"))
        assertFalse(result.sanitizedUrl.contains("si=tracker99"))
        assertTrue(result.sanitizedUrl.contains("content=cybersecurity"))
        assertTrue(result.removedParams.size >= 4)
        assertTrue(result.bytesSaved > 0)
    }

    @Test
    fun testPlatformCoverage() {
        // Must cover 35+ public platforms concurrently
        assertTrue(PlatformReconService.ALL_PLATFORMS.size >= 35)

        val names = PlatformReconService.ALL_PLATFORMS.map { it.name }
        assertTrue(names.contains("GitHub"))
        assertTrue(names.contains("Reddit"))
        assertTrue(names.contains("Telegram"))
        assertTrue(names.contains("Steam"))
        assertTrue(names.contains("Twitch"))
    }
}
