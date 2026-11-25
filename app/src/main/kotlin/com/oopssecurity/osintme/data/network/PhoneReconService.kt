package com.oopssecurity.osintme.data.network

import com.oopssecurity.osintme.data.model.PhoneReconResult

object PhoneReconService {

    private data class CountryDialInfo(
        val dialCode: String,
        val isoCountry: String,
        val countryName: String,
        val defaultTz: String,
        val minNationalDigits: Int = 7,
        val maxNationalDigits: Int = 11
    )

    // 115+ ITU-T E.164 Country Dial Codes sorted longest-prefix first for unambiguous matching
    private val DIAL_CODES = listOf(
        CountryDialInfo("1", "US/CA", "United States / Canada (NANP)", "UTC-4 to UTC-8", 10, 10),
        CountryDialInfo("7", "RU/KZ", "Russia / Kazakhstan", "MSK / UTC+3 to UTC+12", 10, 10),
        CountryDialInfo("20", "EG", "Egypt", "EET (UTC+2)", 9, 10),
        CountryDialInfo("27", "ZA", "South Africa", "SAST (UTC+2)", 9, 9),
        CountryDialInfo("30", "GR", "Greece", "EET (UTC+2 / UTC+3)", 10, 10),
        CountryDialInfo("31", "NL", "Netherlands", "CET (UTC+1 / UTC+2)", 9, 9),
        CountryDialInfo("32", "BE", "Belgium", "CET (UTC+1 / UTC+2)", 8, 9),
        CountryDialInfo("33", "FR", "France", "CET (UTC+1 / UTC+2)", 9, 9),
        CountryDialInfo("34", "ES", "Spain", "CET (UTC+1 / UTC+2)", 9, 9),
        CountryDialInfo("36", "HU", "Hungary", "CET (UTC+1 / UTC+2)", 8, 9),
        CountryDialInfo("39", "IT", "Italy", "CET (UTC+1 / UTC+2)", 9, 10),
        CountryDialInfo("40", "RO", "Romania", "EET (UTC+2 / UTC+3)", 9, 9),
        CountryDialInfo("41", "CH", "Switzerland", "CET (UTC+1 / UTC+2)", 9, 9),
        CountryDialInfo("43", "AT", "Austria", "CET (UTC+1 / UTC+2)", 7, 13),
        CountryDialInfo("44", "GB", "United Kingdom", "GMT / BST (UTC+0 / +1)", 10, 10),
        CountryDialInfo("45", "DK", "Denmark", "CET (UTC+1 / UTC+2)", 8, 8),
        CountryDialInfo("46", "SE", "Sweden", "CET (UTC+1 / UTC+2)", 7, 10),
        CountryDialInfo("47", "NO", "Norway", "CET (UTC+1 / UTC+2)", 8, 8),
        CountryDialInfo("48", "PL", "Poland", "CET (UTC+1 / UTC+2)", 9, 9),
        CountryDialInfo("49", "DE", "Germany", "CET (UTC+1 / UTC+2)", 7, 12),
        CountryDialInfo("51", "PE", "Peru", "PET (UTC-5)", 8, 9),
        CountryDialInfo("52", "MX", "Mexico", "CST (UTC-6)", 10, 10),
        CountryDialInfo("53", "CU", "Cuba", "CST (UTC-5)", 8, 8),
        CountryDialInfo("54", "AR", "Argentina", "ART (UTC-3)", 10, 11),
        CountryDialInfo("55", "BR", "Brazil", "BRT (UTC-3)", 10, 11),
        CountryDialInfo("56", "CL", "Chile", "CLT (UTC-4)", 9, 9),
        CountryDialInfo("57", "CO", "Colombia", "COT (UTC-5)", 10, 10),
        CountryDialInfo("58", "VE", "Venezuela", "VET (UTC-4)", 10, 10),
        CountryDialInfo("60", "MY", "Malaysia", "MYT (UTC+8)", 9, 10),
        CountryDialInfo("61", "AU", "Australia", "AEST / AWST (UTC+8 to +11)", 9, 9),
        CountryDialInfo("62", "ID", "Indonesia", "WIB / WITA (UTC+7 to +9)", 9, 12),
        CountryDialInfo("63", "PH", "Philippines", "PHT (UTC+8)", 10, 10),
        CountryDialInfo("64", "NZ", "New Zealand", "NZST (UTC+12)", 8, 10),
        CountryDialInfo("65", "SG", "Singapore", "SGT (UTC+8)", 8, 8),
        CountryDialInfo("66", "TH", "Thailand", "ICT (UTC+7)", 9, 9),
        CountryDialInfo("81", "JP", "Japan", "JST (UTC+9)", 9, 10),
        CountryDialInfo("82", "KR", "South Korea", "KST (UTC+9)", 9, 10),
        CountryDialInfo("84", "VN", "Vietnam", "ICT (UTC+7)", 9, 10),
        CountryDialInfo("86", "CN", "China", "CST (UTC+8)", 11, 11),
        CountryDialInfo("90", "TR", "Turkey", "TRT (UTC+3)", 10, 10),
        CountryDialInfo("91", "IN", "India", "IST (UTC+5:30)", 10, 10),
        CountryDialInfo("92", "PK", "Pakistan", "PKT (UTC+5)", 10, 10),
        CountryDialInfo("93", "AF", "Afghanistan", "AFT (UTC+4:30)", 9, 9),
        CountryDialInfo("94", "LK", "Sri Lanka", "SLST (UTC+5:30)", 9, 9),
        CountryDialInfo("95", "MM", "Myanmar", "MMT (UTC+6:30)", 8, 10),
        CountryDialInfo("98", "IR", "Iran", "IRST (UTC+3:30)", 10, 10),
        CountryDialInfo("212", "MA", "Morocco", "WET (UTC+1)", 9, 9),
        CountryDialInfo("213", "DZ", "Algeria", "CET (UTC+1)", 9, 9),
        CountryDialInfo("216", "TN", "Tunisia", "CET (UTC+1)", 8, 8),
        CountryDialInfo("218", "LY", "Libya", "EET (UTC+2)", 9, 10),
        CountryDialInfo("220", "GM", "Gambia", "GMT (UTC+0)", 7, 7),
        CountryDialInfo("221", "SN", "Senegal", "GMT (UTC+0)", 9, 9),
        CountryDialInfo("233", "GH", "Ghana", "GMT (UTC+0)", 9, 9),
        CountryDialInfo("234", "NG", "Nigeria", "WAT (UTC+1)", 10, 10),
        CountryDialInfo("237", "CM", "Cameroon", "WAT (UTC+1)", 9, 9),
        CountryDialInfo("251", "ET", "Ethiopia", "EAT (UTC+3)", 9, 9),
        CountryDialInfo("254", "KE", "Kenya", "EAT (UTC+3)", 9, 9),
        CountryDialInfo("255", "TZ", "Tanzania", "EAT (UTC+3)", 9, 9),
        CountryDialInfo("256", "UG", "Uganda", "EAT (UTC+3)", 9, 9),
        CountryDialInfo("260", "ZM", "Zambia", "CAT (UTC+2)", 9, 9),
        CountryDialInfo("263", "ZW", "Zimbabwe", "CAT (UTC+2)", 9, 9),
        CountryDialInfo("351", "PT", "Portugal", "WET (UTC+0 / +1)", 9, 9),
        CountryDialInfo("352", "LU", "Luxembourg", "CET (UTC+1 / +2)", 8, 9),
        CountryDialInfo("353", "IE", "Ireland", "GMT / IST (UTC+0 / +1)", 9, 9),
        CountryDialInfo("354", "IS", "Iceland", "GMT (UTC+0)", 7, 7),
        CountryDialInfo("355", "AL", "Albania", "CET (UTC+1 / +2)", 8, 9),
        CountryDialInfo("356", "MT", "Malta", "CET (UTC+1 / +2)", 8, 8),
        CountryDialInfo("357", "CY", "Cyprus", "EET (UTC+2 / +3)", 8, 8),
        CountryDialInfo("358", "FI", "Finland", "EET (UTC+2 / +3)", 7, 10),
        CountryDialInfo("359", "BG", "Bulgaria", "EET (UTC+2 / +3)", 8, 9),
        CountryDialInfo("370", "LT", "Lithuania", "EET (UTC+2 / +3)", 8, 8),
        CountryDialInfo("371", "LV", "Latvia", "EET (UTC+2 / +3)", 8, 8),
        CountryDialInfo("372", "EE", "Estonia", "EET (UTC+2 / +3)", 7, 8),
        CountryDialInfo("373", "MD", "Moldova", "EET (UTC+2 / +3)", 8, 8),
        CountryDialInfo("374", "AM", "Armenia", "AMT (UTC+4)", 8, 8),
        CountryDialInfo("375", "BY", "Belarus", "MSK (UTC+3)", 9, 9),
        CountryDialInfo("380", "UA", "Ukraine", "EET (UTC+2 / +3)", 9, 9),
        CountryDialInfo("381", "RS", "Serbia", "CET (UTC+1 / +2)", 8, 9),
        CountryDialInfo("385", "HR", "Croatia", "CET (UTC+1 / +2)", 8, 9),
        CountryDialInfo("386", "SI", "Slovenia", "CET (UTC+1 / +2)", 8, 8),
        CountryDialInfo("387", "BA", "Bosnia and Herzegovina", "CET (UTC+1 / +2)", 8, 9),
        CountryDialInfo("420", "CZ", "Czech Republic", "CET (UTC+1 / +2)", 9, 9),
        CountryDialInfo("421", "SK", "Slovakia", "CET (UTC+1 / +2)", 9, 9),
        CountryDialInfo("502", "GT", "Guatemala", "CST (UTC-6)", 8, 8),
        CountryDialInfo("503", "SV", "El Salvador", "CST (UTC-6)", 8, 8),
        CountryDialInfo("504", "HN", "Honduras", "CST (UTC-6)", 8, 8),
        CountryDialInfo("505", "NI", "Nicaragua", "CST (UTC-6)", 8, 8),
        CountryDialInfo("506", "CR", "Costa Rica", "CST (UTC-6)", 8, 8),
        CountryDialInfo("507", "PA", "Panama", "EST (UTC-5)", 7, 8),
        CountryDialInfo("591", "BO", "Bolivia", "BOT (UTC-4)", 8, 8),
        CountryDialInfo("593", "EC", "Ecuador", "ECT (UTC-5)", 9, 9),
        CountryDialInfo("595", "PY", "Paraguay", "PYT (UTC-4)", 9, 9),
        CountryDialInfo("598", "UY", "Uruguay", "UYT (UTC-3)", 8, 8),
        CountryDialInfo("852", "HK", "Hong Kong", "HKT (UTC+8)", 8, 8),
        CountryDialInfo("853", "MO", "Macau", "CST (UTC+8)", 8, 8),
        CountryDialInfo("855", "KH", "Cambodia", "ICT (UTC+7)", 8, 9),
        CountryDialInfo("856", "LA", "Laos", "ICT (UTC+7)", 8, 10),
        CountryDialInfo("880", "BD", "Bangladesh", "BST (UTC+6)", 10, 10),
        CountryDialInfo("886", "TW", "Taiwan", "CST (UTC+8)", 9, 9),
        CountryDialInfo("960", "MV", "Maldives", "MVT (UTC+5)", 7, 7),
        CountryDialInfo("961", "LB", "Lebanon", "EET (UTC+2 / +3)", 7, 8),
        CountryDialInfo("962", "JO", "Jordan", "EET (UTC+3)", 9, 9),
        CountryDialInfo("963", "SY", "Syria", "EET (UTC+3)", 8, 9),
        CountryDialInfo("964", "IQ", "Iraq", "AST (UTC+3)", 10, 10),
        CountryDialInfo("965", "KW", "Kuwait", "AST (UTC+3)", 8, 8),
        CountryDialInfo("966", "SA", "Saudi Arabia", "AST (UTC+3)", 9, 9),
        CountryDialInfo("967", "YE", "Yemen", "AST (UTC+3)", 9, 9),
        CountryDialInfo("968", "OM", "Oman", "GST (UTC+4)", 8, 8),
        CountryDialInfo("971", "AE", "United Arab Emirates", "GST (UTC+4)", 9, 9),
        CountryDialInfo("972", "IL", "Israel", "IST (UTC+2 / +3)", 9, 9),
        CountryDialInfo("973", "BH", "Bahrain", "AST (UTC+3)", 8, 8),
        CountryDialInfo("974", "QA", "Qatar", "AST (UTC+3)", 8, 8),
        CountryDialInfo("975", "BT", "Bhutan", "BTT (UTC+6)", 8, 8),
        CountryDialInfo("976", "MN", "Mongolia", "ULAT (UTC+8)", 8, 8),
        CountryDialInfo("977", "NP", "Nepal", "NPT (UTC+5:45)", 10, 10),
        CountryDialInfo("994", "AZ", "Azerbaijan", "AZT (UTC+4)", 9, 9),
        CountryDialInfo("995", "GE", "Georgia", "GET (UTC+4)", 9, 9),
        CountryDialInfo("998", "UZ", "Uzbekistan", "UZT (UTC+5)", 9, 9)
    ).sortedByDescending { it.dialCode.length }

    fun analyzeNumber(rawNumber: String): Result<PhoneReconResult> {
        return try {
            val cleaned = rawNumber.trim()
            val normalizedPrefix = if (cleaned.startsWith("00")) "+${cleaned.removePrefix("00")}" else cleaned
            val digitsOnly = normalizedPrefix.replace(Regex("[^0-9]"), "")

            if (digitsOnly.length < 7 || digitsOnly.length > 15) {
                return Result.failure(
                    IllegalArgumentException("ITU-T E.164 numbers must contain between 7 and 15 digits.")
                )
            }

            var matchedCountry: CountryDialInfo? = null
            var nationalNumber = digitsOnly

            if (normalizedPrefix.startsWith("+")) {
                for (info in DIAL_CODES) {
                    if (digitsOnly.startsWith(info.dialCode)) {
                        matchedCountry = info
                        nationalNumber = digitsOnly.removePrefix(info.dialCode)
                        break
                    }
                }
            } else {
                for (info in DIAL_CODES) {
                    if (digitsOnly.startsWith(info.dialCode)) {
                        val remainderLen = digitsOnly.length - info.dialCode.length
                        if (remainderLen in info.minNationalDigits..info.maxNationalDigits) {
                            matchedCountry = info
                            nationalNumber = digitsOnly.removePrefix(info.dialCode)
                            break
                        }
                    }
                }
            }

            val country = matchedCountry
                ?: CountryDialInfo("?", "XX", "Unrecognized Country Prefix (include +code)", "UTC", 7, 15)

            val e164 = when {
                normalizedPrefix.startsWith("+") -> "+$digitsOnly"
                matchedCountry != null -> "+${country.dialCode}$nationalNumber"
                else -> "+$digitsOnly"
            }
            val e164Digits = e164.removePrefix("+")
            val isValidLength = matchedCountry != null &&
                nationalNumber.length in country.minNationalDigits..country.maxNationalDigits

            val nationalFormatted = formatNational(country.isoCountry, nationalNumber)
            val (lineType, numberingNote) = analyzeNumberingPlan(country, nationalNumber, isValidLength)

            Result.success(
                PhoneReconResult(
                    rawInput = rawNumber,
                    e164Format = e164,
                    nationalFormat = nationalFormatted,
                    countryName = country.countryName,
                    countryCode = country.isoCountry,
                    dialCode = if (country.dialCode != "?") "+${country.dialCode}" else "Unknown",
                    lineType = lineType,
                    numberingPlanNote = numberingNote,
                    timezone = country.defaultTz,
                    isValidLength = isValidLength,
                    whatsappUrl = "https://wa.me/$e164Digits",
                    telegramUrl = "https://t.me/+$e164Digits"
                )
            )
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    private fun formatNational(isoCountry: String, nationalDigits: String): String {
        return when (isoCountry) {
            "US/CA" -> if (nationalDigits.length == 10) {
                "(${nationalDigits.substring(0, 3)}) ${nationalDigits.substring(3, 6)}-${nationalDigits.substring(6)}"
            } else nationalDigits
            "IN" -> if (nationalDigits.length == 10) {
                "${nationalDigits.substring(0, 5)} ${nationalDigits.substring(5)}"
            } else nationalDigits
            "GB" -> if (nationalDigits.length == 10) {
                "${nationalDigits.substring(0, 4)} ${nationalDigits.substring(4)}"
            } else nationalDigits
            "FR", "ES", "NL", "CH", "PL", "PT" -> if (nationalDigits.length == 9) {
                "${nationalDigits.substring(0, 3)} ${nationalDigits.substring(3, 6)} ${nationalDigits.substring(6)}"
            } else nationalDigits
            else -> nationalDigits.chunked(3).joinToString(" ")
        }
    }

    private fun analyzeNumberingPlan(
        country: CountryDialInfo,
        nationalDigits: String,
        isValidLength: Boolean
    ): Pair<String, String> {
        if (!isValidLength) {
            val expected = if (country.minNationalDigits == country.maxNationalDigits) {
                "${country.minNationalDigits} national digits"
            } else {
                "${country.minNationalDigits}–${country.maxNationalDigits} national digits"
            }
            return "Length Mismatch" to "Received ${nationalDigits.length} national digits; ITU-T plan expects $expected for ${country.countryName}."
        }

        return when (country.isoCountry) {
            "IN" -> {
                val first = nationalDigits.firstOrNull()
                if (first in listOf('6', '7', '8', '9')) {
                    "Mobile (ITU-T / TRAI)" to "Prefix '${nationalDigits.take(2)}xx' falls in India's 10-digit cellular allocation (6–9 series). Live MNP carrier routing requires paid HLR lookup."
                } else {
                    "Geographic Fixed Line" to "Prefix '${nationalDigits.take(3)}' indicates an STD fixed-line subscriber range under India's National Numbering Plan."
                }
            }
            "US/CA" -> {
                val npa = nationalDigits.take(3)
                val tollFree = setOf("800", "888", "877", "866", "855", "844", "833")
                when {
                    npa in tollFree -> "Toll-Free Service (NANP)" to "Area code $npa is a reserved North American toll-free routing prefix."
                    npa == "900" -> "Premium Rate Service" to "Area code 900 is assigned to pay-per-call premium services."
                    else -> "Mobile / Landline / VoIP (NANP)" to "NANPA area code $npa. Because North America supports full mobile/landline portability, live carrier identification requires CNAM/LRN lookup."
                }
            }
            "GB" -> when {
                nationalDigits.startsWith("7") -> "Mobile / Personal Numbering" to "UK 07xxx range is allocated by Ofcom for cellular mobile & personal numbering."
                nationalDigits.startsWith("1") || nationalDigits.startsWith("2") -> "Geographic Fixed Line" to "UK 01/02 range is allocated for geographic landline exchanges."
                nationalDigits.startsWith("800") || nationalDigits.startsWith("808") -> "Freephone" to "Ofcom toll-free consumer range."
                else -> "Non-Geographic Service" to "Ofcom UK national numbering allocation."
            }
            "DE" -> when {
                nationalDigits.startsWith("15") || nationalDigits.startsWith("16") || nationalDigits.startsWith("17") ->
                    "Mobile (Bundesnetzagentur)" to "German 015x–017x prefix block is reserved for cellular mobile networks."
                else -> "Geographic / Service Line" to "German national numbering plan allocation."
            }
            "AU" -> when {
                nationalDigits.startsWith("4") -> "Mobile (ACMA)" to "Australian 04xx range is allocated for mobile cellular services."
                else -> "Geographic Fixed Line" to "Australian ACMA geographic area range."
            }
            else -> "Valid E.164 Allocation" to "Matches ITU-T E.164 numbering length for ${country.countryName}. Real-time carrier attribution requires live HLR/MNP query (not guessed offline)."
        }
    }
}
