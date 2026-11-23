package com.oopssecurity.osintme.data.network

import com.oopssecurity.osintme.data.model.PhoneReconResult

object PhoneReconService {

    private data class CountryDialInfo(
        val dialCode: String,
        val isoCountry: String,
        val countryName: String,
        val defaultTz: String
    )

    private val DIAL_CODES = listOf(
        CountryDialInfo("1", "US", "United States / Canada", "UTC-4 to UTC-8"),
        CountryDialInfo("44", "GB", "United Kingdom", "UTC+0 / BST"),
        CountryDialInfo("91", "IN", "India", "IST (UTC+5:30)"),
        CountryDialInfo("61", "AU", "Australia", "AEST / AWST (UTC+8 to UTC+11)"),
        CountryDialInfo("49", "DE", "Germany", "CET (UTC+1 / UTC+2)"),
        CountryDialInfo("33", "FR", "France", "CET (UTC+1 / UTC+2)"),
        CountryDialInfo("81", "JP", "Japan", "JST (UTC+9)"),
        CountryDialInfo("86", "CN", "China", "CST (UTC+8)"),
        CountryDialInfo("7", "RU", "Russia / Kazakhstan", "MSK / UTC+3 to UTC+12"),
        CountryDialInfo("55", "BR", "Brazil", "BRT (UTC-3)"),
        CountryDialInfo("971", "AE", "United Arab Emirates", "GST (UTC+4)"),
        CountryDialInfo("966", "SA", "Saudi Arabia", "AST (UTC+3)"),
        CountryDialInfo("234", "NG", "Nigeria", "WAT (UTC+1)"),
        CountryDialInfo("27", "ZA", "South Africa", "SAST (UTC+2)"),
        CountryDialInfo("92", "PK", "Pakistan", "PKT (UTC+5)"),
        CountryDialInfo("880", "BD", "Bangladesh", "BST (UTC+6)"),
        CountryDialInfo("62", "ID", "Indonesia", "WIB / WITA (UTC+7 to UTC+9)"),
        CountryDialInfo("63", "PH", "Philippines", "PHT (UTC+8)"),
        CountryDialInfo("84", "VN", "Vietnam", "ICT (UTC+7)"),
        CountryDialInfo("90", "TR", "Turkey", "TRT (UTC+3)"),
        CountryDialInfo("39", "IT", "Italy", "CET (UTC+1 / UTC+2)"),
        CountryDialInfo("34", "ES", "Spain", "CET (UTC+1 / UTC+2)"),
        CountryDialInfo("31", "NL", "Netherlands", "CET (UTC+1 / UTC+2)"),
        CountryDialInfo("41", "CH", "Switzerland", "CET (UTC+1 / UTC+2)"),
        CountryDialInfo("46", "SE", "Sweden", "CET (UTC+1 / UTC+2)"),
        CountryDialInfo("47", "NO", "Norway", "CET (UTC+1 / UTC+2)"),
        CountryDialInfo("48", "PL", "Poland", "CET (UTC+1 / UTC+2)"),
        CountryDialInfo("65", "SG", "Singapore", "SGT (UTC+8)"),
        CountryDialInfo("60", "MY", "Malaysia", "MYT (UTC+8)"),
        CountryDialInfo("64", "NZ", "New Zealand", "NZST (UTC+12)"),
        CountryDialInfo("52", "MX", "Mexico", "CST (UTC-6)"),
        CountryDialInfo("54", "AR", "Argentina", "ART (UTC-3)"),
        CountryDialInfo("57", "CO", "Colombia", "COT (UTC-5)"),
        CountryDialInfo("20", "EG", "Egypt", "EET (UTC+2)"),
        CountryDialInfo("98", "IR", "Iran", "IRST (UTC+3:30)"),
        CountryDialInfo("972", "IL", "Israel", "IDT (UTC+3)"),
        CountryDialInfo("82", "KR", "South Korea", "KST (UTC+9)"),
        CountryDialInfo("380", "UA", "Ukraine", "EET (UTC+2 / UTC+3)")
    ).sortedByDescending { it.dialCode.length } // Longest dial code matches first (e.g. 880 before 8)

    fun analyzeNumber(rawNumber: String): Result<PhoneReconResult> {
        return try {
            val cleaned = rawNumber.trim()
            val digitsOnly = cleaned.replace(Regex("[^0-9]"), "")

            if (digitsOnly.length < 7 || digitsOnly.length > 15) {
                return Result.failure(IllegalArgumentException("Number must contain between 7 and 15 digits"))
            }

            // Find matching dial code
            var matchedCountry: CountryDialInfo? = null
            var nationalNumber = digitsOnly

            if (cleaned.startsWith("+")) {
                for (info in DIAL_CODES) {
                    if (digitsOnly.startsWith(info.dialCode)) {
                        matchedCountry = info
                        nationalNumber = digitsOnly.removePrefix(info.dialCode)
                        break
                    }
                }
            } else {
                // If no leading '+', check if starts with known dial code or fallback
                for (info in DIAL_CODES) {
                    if (digitsOnly.startsWith(info.dialCode) && digitsOnly.length > info.dialCode.length + 6) {
                        matchedCountry = info
                        nationalNumber = digitsOnly.removePrefix(info.dialCode)
                        break
                    }
                }
            }

            // Default fallback if unknown dial code
            val country = matchedCountry ?: CountryDialInfo("?", "XX", "International / Unassigned", "UTC")
            val e164 = if (cleaned.startsWith("+")) "+$digitsOnly" else "+${country.dialCode}$nationalNumber"
            val e164Digits = e164.removePrefix("+")

            // Format national number
            val nationalFormatted = formatNational(country.isoCountry, nationalNumber)

            // Line type & carrier heuristics
            val (lineType, carrierEstimate) = determineLineTypeAndCarrier(country.isoCountry, nationalNumber)

            val whatsapp = "https://wa.me/$e164Digits"
            val telegram = "https://t.me/+$e164Digits"

            Result.success(
                PhoneReconResult(
                    rawInput = rawNumber,
                    e164Format = e164,
                    nationalFormat = nationalFormatted,
                    countryName = country.countryName,
                    countryCode = country.isoCountry,
                    lineType = lineType,
                    carrierEstimate = carrierEstimate,
                    timezone = country.defaultTz,
                    whatsappUrl = whatsapp,
                    telegramUrl = telegram
                )
            )
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    private fun formatNational(isoCountry: String, nationalDigits: String): String {
        return when (isoCountry) {
            "US" -> {
                if (nationalDigits.length == 10) {
                    "(${nationalDigits.substring(0, 3)}) ${nationalDigits.substring(3, 6)}-${nationalDigits.substring(6)}"
                } else nationalDigits
            }
            "IN" -> {
                if (nationalDigits.length == 10) {
                    "${nationalDigits.substring(0, 5)} ${nationalDigits.substring(5)}"
                } else nationalDigits
            }
            "GB" -> {
                if (nationalDigits.length == 10) {
                    "${nationalDigits.substring(0, 4)} ${nationalDigits.substring(4)}"
                } else nationalDigits
            }
            else -> nationalDigits
        }
    }

    private fun determineLineTypeAndCarrier(isoCountry: String, nationalDigits: String): Pair<String, String> {
        return when (isoCountry) {
            "IN" -> {
                if (nationalDigits.length == 10) {
                    val firstDigit = nationalDigits.first()
                    if (firstDigit in listOf('6', '7', '8', '9')) {
                        val prefix = nationalDigits.substring(0, 2)
                        val carrier = when (prefix) {
                            "98", "99", "97", "96", "95", "94" -> "Airtel / BSNL / Vi Network Range"
                            "70", "79", "80", "81", "82", "83", "84", "85", "86", "87", "88", "89" -> "Jio / Vi / Airtel LTE Range"
                            "62", "63" -> "Reliance Jio Infocomm Range"
                            else -> "GSM Cellular Mobile Network"
                        }
                        "Mobile / Cellular (GSM/LTE)" to carrier
                    } else {
                        "Fixed Line / Landline" to "BSNL / MTNL / Airtel Fixed"
                    }
                } else {
                    "Cellular / Fixed" to "Indian Telecom Range"
                }
            }
            "US" -> {
                if (nationalDigits.length == 10) {
                    val npa = nationalDigits.substring(0, 3)
                    val tollFree = listOf("800", "888", "877", "866", "855", "844", "833")
                    if (npa in tollFree) {
                        "Toll-Free / Virtual Service" to "Enterprise Toll-Free Routing"
                    } else {
                        "Cellular / Wireless / VoIP" to "NANPA Exchange Block ($npa)"
                    }
                } else {
                    "NANP Line" to "North American Range"
                }
            }
            "GB" -> {
                if (nationalDigits.startsWith("7")) {
                    "Mobile / Cellular" to "UK Mobile (EE, O2, Vodafone, Three)"
                } else if (nationalDigits.startsWith("1") || nationalDigits.startsWith("2")) {
                    "Geographic Fixed Line" to "BT / Virgin Media Fixed Network"
                } else if (nationalDigits.startsWith("800")) {
                    "Freephone / Business" to "UK Toll-Free Network"
                } else {
                    "National UK Service" to "Ofcom Numbering Block"
                }
            }
            else -> {
                "Cellular / Public Switched" to "National Telephony Network"
            }
        }
    }
}
