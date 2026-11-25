package com.oopssecurity.osintme.util

import java.net.URI

enum class InputType(val label: String, val description: String) {
    EMAIL("Email", "Full breach, Gravatar & domain dossier"),
    IP_ADDRESS("IPv4 Address", "Ports, BGP/ASN, threat & BYOK dossier"),
    DOMAIN("Domain / Host", "DNS, TLS, web stack, BGP, subdomains & threat dossier"),
    PHONE_NUMBER("Phone Number", "Identify carrier, location & messaging pivots"),
    TRACKING_URL("URL / Link", "Redirect chain, threat check & host dossier"),
    HASH("File Hash", "MalwareBazaar & VirusTotal hash reputation"),
    USERNAME("Username", "Deep hunt across 106+ sites, GitHub & Keybase"),
    GENERIC_KEYWORD("Person / Org", "Universal Wiki, GitHub, HN, Reddit & handle dossier")
}

object InputClassifier {
    private val EMAIL_REGEX = Regex("^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$")
    private val IPV4_REGEX = Regex("^((25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d)\\.?\\b){4}$")
    private val DOMAIN_REGEX = Regex("^([a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,}$")
    private val HASH_REGEX = Regex("^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
    private val TRACKER_PARAMS = listOf("utm_", "si=", "igsh=", "fbclid=", "gclid=", "ref=", "ref_src=", "mc_eid=", "trk=")

    fun classify(rawInput: String): InputType {
        val input = rawInput.trim()
        if (input.isEmpty()) return InputType.GENERIC_KEYWORD

        if (EMAIL_REGEX.matches(input)) {
            return InputType.EMAIL
        }

        if (IPV4_REGEX.matches(input)) {
            return InputType.IP_ADDRESS
        }

        if (HASH_REGEX.matches(input)) {
            return InputType.HASH
        }

        val digitsOnly = input.replace(Regex("[\\s-()]"), "")
        if (input.startsWith("+") && digitsOnly.drop(1).matches(Regex("^\\d{7,15}$"))) {
            return InputType.PHONE_NUMBER
        }
        if (digitsOnly.matches(Regex("^\\d{10,15}$"))) {
            return InputType.PHONE_NUMBER
        }

        if (input.startsWith("http://") || input.startsWith("https://")) {
            val lower = input.lowercase()
            if (TRACKER_PARAMS.any { lower.contains(it) }) {
                return InputType.TRACKING_URL
            }
            return try {
                val uri = URI(input)
                val host = uri.host ?: ""
                if (IPV4_REGEX.matches(host)) InputType.IP_ADDRESS
                else if (DOMAIN_REGEX.matches(host)) InputType.DOMAIN
                else InputType.TRACKING_URL
            } catch (e: Exception) {
                InputType.TRACKING_URL
            }
        }

        if (DOMAIN_REGEX.matches(input)) {
            return InputType.DOMAIN
        }

        if (input.matches(Regex("^[a-zA-Z0-9_.-]{3,30}$"))) {
            return InputType.USERNAME
        }

        return InputType.GENERIC_KEYWORD
    }
}
