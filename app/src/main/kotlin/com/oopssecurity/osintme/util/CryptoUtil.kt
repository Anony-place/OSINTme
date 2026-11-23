package com.oopssecurity.osintme.util

import java.security.MessageDigest

object CryptoUtil {
    /**
     * Compute SHA-1 hash of a string strictly in-memory.
     * The input password never leaves memory or the device.
     */
    fun sha1(input: String): String {
        val md = MessageDigest.getInstance("SHA-1")
        val bytes = md.digest(input.toByteArray(Charsets.UTF_8))
        return bytes.joinToString("") { "%02X".format(it) }
    }

    fun md5(input: String): String {
        val md = MessageDigest.getInstance("MD5")
        val bytes = md.digest(input.toByteArray(Charsets.UTF_8))
        return bytes.joinToString("") { "%02x".format(it) }
    }
}
