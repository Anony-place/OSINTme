package com.oopssecurity.osintme

import com.oopssecurity.osintme.data.local.AiProtocol
import com.oopssecurity.osintme.data.model.InvestigationCase
import com.oopssecurity.osintme.data.model.ScanArtifact
import com.oopssecurity.osintme.data.network.AlienVaultOtxService
import com.oopssecurity.osintme.data.network.ByokAiService
import com.oopssecurity.osintme.data.network.DeepWebCrawlerService
import com.oopssecurity.osintme.data.network.EmailAndIdentityIntelService
import com.oopssecurity.osintme.data.network.PhoneReconService
import com.oopssecurity.osintme.data.network.PlatformReconService
import com.oopssecurity.osintme.data.network.RedirectHeaderService
import com.oopssecurity.osintme.data.network.TlsAndTakeoverService
import com.oopssecurity.osintme.data.network.WaybackCategory
import com.oopssecurity.osintme.data.network.WaybackCdxService
import com.oopssecurity.osintme.data.network.WebTechReconService
import com.oopssecurity.osintme.util.CaseReportExporter
import com.oopssecurity.osintme.util.CryptoUtil
import com.oopssecurity.osintme.util.EmailHeaderAnalyzer
import com.oopssecurity.osintme.util.HashFormat
import com.oopssecurity.osintme.util.InputClassifier
import com.oopssecurity.osintme.util.InputType
import com.oopssecurity.osintme.util.IocCategory
import com.oopssecurity.osintme.util.IocExtractor
import com.oopssecurity.osintme.util.NetworkSecurityGuard
import com.oopssecurity.osintme.util.PayloadDecoder
import com.oopssecurity.osintme.util.PivotEngine
import com.oopssecurity.osintme.util.PivotEntityType
import com.oopssecurity.osintme.util.PivotTargetModule
import com.oopssecurity.osintme.util.SafeBrowserLauncher
import com.oopssecurity.osintme.util.UrlSanitizer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
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
        assertEquals(InputType.HASH, InputClassifier.classify("d41d8cd98f00b204e9800998ecf8427e"))
        assertEquals(InputType.HASH, InputClassifier.classify("da39a3ee5e6b4b0d3255bfef95601890afd80709"))
        assertEquals(InputType.HASH, InputClassifier.classify("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))
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
        // Must cover 100+ verified public platforms concurrently with unique names
        assertTrue(PlatformReconService.ALL_PLATFORMS.size >= 100)

        val names = PlatformReconService.ALL_PLATFORMS.map { it.name }
        assertEquals(names.size, names.toSet().size)
        assertTrue(names.contains("GitHub"))
        assertTrue(names.contains("Reddit"))
        assertTrue(names.contains("Telegram"))
        assertTrue(names.contains("Steam"))
        assertTrue(names.contains("Twitch"))
        assertTrue(names.contains("HackerOne"))
        assertTrue(names.contains("Codeberg"))
        assertTrue(names.contains("Bitbucket"))
        assertTrue(names.contains("Duolingo"))
    }

    @Test
    fun testPhoneReconE164Parsing() {
        val usResult = PhoneReconService.analyzeNumber("+1 (415) 555-0199").getOrThrow()
        assertEquals("+1", usResult.dialCode)
        assertTrue(usResult.isValidLength)
        assertTrue(usResult.countryName.contains("United States"))

        val inResult = PhoneReconService.analyzeNumber("+91 98765 43210").getOrThrow()
        assertEquals("+91", inResult.dialCode)
        assertTrue(inResult.isValidLength)
        assertEquals("India", inResult.countryName)
        assertTrue(inResult.lineType.contains("Mobile"))

        val shortResult = PhoneReconService.analyzeNumber("+44 123")
        assertTrue(shortResult.isFailure || !shortResult.getOrThrow().isValidLength)
    }

    @Test
    fun testPivotEngineNormalizationAndDefanging() {
        // Wildcard SAN & trailing dot normalization
        val sanEntity = PivotEngine.normalize("*.api.example.com.", PivotEntityType.DOMAIN)
        assertEquals("api.example.com", sanEntity.normalizedValue)
        assertEquals(PivotEntityType.DOMAIN, sanEntity.type)

        // MX priority extraction
        val mxEntity = PivotEngine.normalize("10 alt1.aspmx.l.google.com.", PivotEntityType.DOMAIN)
        assertEquals("alt1.aspmx.l.google.com", mxEntity.normalizedValue)

        // Email splits into username + domain pivots + Target Dossier
        val emailEntity = PivotEngine.normalize("Alice@Example.ORG")
        assertEquals(PivotEntityType.EMAIL, emailEntity.type)
        val emailActions = PivotEngine.buildActions(emailEntity)
        assertTrue(emailActions.any { it.module == PivotTargetModule.TARGET_DOSSIER })
        assertTrue(emailActions.any { it.module == PivotTargetModule.USERNAME_RECON && it.targetValue == "alice" })
        assertTrue(emailActions.any { it.module == PivotTargetModule.DOMAIN_RECON && it.targetValue == "example.org" })

        // URL extracts host for Domain & Threat pivots
        val urlEntity = PivotEngine.normalize("https://sub.target.io/login?id=1")
        assertEquals(PivotEntityType.URL, urlEntity.type)
        val urlActions = PivotEngine.buildActions(urlEntity)
        assertTrue(urlActions.any { it.module == PivotTargetModule.DOMAIN_RECON && it.targetValue == "sub.target.io" })
        assertTrue(urlActions.any { it.module == PivotTargetModule.THREAT_INTEL && it.targetValue == "sub.target.io" })

        // Hash routes to Target Dossier and Hash/Payload Lab
        val sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        val hashEntity = PivotEngine.normalize(sha256)
        assertEquals(PivotEntityType.HASH, hashEntity.type)
        val hashActions = PivotEngine.buildActions(hashEntity)
        assertTrue(hashActions.any { it.module == PivotTargetModule.TARGET_DOSSIER && it.targetValue == sha256 })
        assertTrue(hashActions.any { it.module == PivotTargetModule.HASH_PAYLOAD && it.targetValue == sha256 })

        // Defanging
        assertEquals("hxxps://evil[.]example[.]com/path", PivotEngine.defang("https://evil.example.com/path"))
        assertEquals("user[@]corp[.]net", PivotEngine.defang("user@corp.net"))
        assertEquals("1[.]1[.]1[.]1", PivotEngine.defang("1.1.1.1"))
    }

    @Test
    fun testIocExtractorAndCsvNeutralization() {
        val sampleLog = """
            Alert: beacon to hxxps://c2[.]evil-actor[.]io/stage2 from 198[.]51[.]100[.]42
            Contact: phisher[@]spoofed-bank[.]com
            Payload SHA256: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
            Wallet: 0x742d35Cc6634C0532925a3b844Bc454e4438f44e
        """.trimIndent()

        val result = IocExtractor.extract(sampleLog)
        assertTrue(result.items.any { it.category == IocCategory.URL && it.value == "https://c2.evil-actor.io/stage2" })
        assertTrue(result.items.any { it.category == IocCategory.IPV4 && it.value == "198.51.100.42" })
        assertTrue(result.items.any { it.category == IocCategory.EMAIL && it.value == "phisher@spoofed-bank.com" })
        assertTrue(result.items.any { it.category == IocCategory.DOMAIN && it.value == "c2.evil-actor.io" })
        assertTrue(result.items.any { it.category == IocCategory.SHA256 })
        assertTrue(result.items.any { it.category == IocCategory.CRYPTO_WALLET })

        // Verify CSV formula injection neutralization
        val dangerous = listOf(
            com.oopssecurity.osintme.util.ExtractedIoc(
                value = "=cmd|' /C calc'!A0",
                defangedValue = "=cmd|' /C calc'!A0",
                category = IocCategory.DOMAIN
            )
        )
        val csv = IocExtractor.toCsv(dangerous, defanged = false)
        assertTrue(csv.contains("\"'=cmd"))
    }

    @Test
    fun testEmailHeaderForensicsSpoofingDetection() {
        val rawHeaders = """
            Return-Path: <bounce@attacker-mailer.xyz>
            Received: from mx.victim.org (mx.victim.org [203.0.113.10])
                by inbox.victim.org with ESMTPS; Tue, 10 Nov 2026 10:15:00 +0000
            Received: from evil-relay.attacker-mailer.xyz ([198.51.100.77])
                by mx.victim.org with ESMTP; Tue, 10 Nov 2026 10:00:00 +0000
            Authentication-Results: mx.victim.org;
                spf=fail smtp.mailfrom=attacker-mailer.xyz;
                dkim=fail header.i=@trusted-bank.com;
                dmarc=fail action=reject header.from=trusted-bank.com
            From: Security Team <alerts@trusted-bank.com>
            Reply-To: urgent@collect-creds.xyz
            Subject: Urgent Wire Transfer
        """.trimIndent()

        val report = EmailHeaderAnalyzer.analyze(rawHeaders)
        assertEquals("trusted-bank.com", report.fromDomain)
        assertEquals("attacker-mailer.xyz", report.returnPathDomain)
        assertEquals("collect-creds.xyz", report.replyToDomain)
        assertEquals(2, report.hops.size)
        assertEquals("198.51.100.77", report.hops[0].ipAddress)
        assertEquals("HIGH", report.riskVerdict)
        assertTrue(report.authChecks.any { it.mechanism == "SPF" && it.status == "FAIL" })
        assertTrue(report.authChecks.any { it.mechanism == "DMARC" && it.status == "FAIL" })
        assertTrue(report.spoofingAlerts.any { it.contains("Return-Path mismatch") })
        assertTrue(report.spoofingAlerts.any { it.contains("Reply-To diversion") })
        assertTrue(report.hops[1].isDelayAnomaly) // 15 min delay > 10 min threshold
    }

    @Test
    fun testPayloadDecoderAndJwtInspection() {
        val b64 = PayloadDecoder.encodeBase64("OSINTme-Payload")
        assertEquals("OSINTme-Payload", PayloadDecoder.decodeBase64(b64).getOrThrow())

        val hex = PayloadDecoder.encodeHex("ABC")
        assertEquals("414243", hex)
        assertEquals("ABC", PayloadDecoder.decodeHex(hex).getOrThrow())

        assertEquals("Hello World", PayloadDecoder.rot13(PayloadDecoder.rot13("Hello World")))

        val hashes = PayloadDecoder.computeHashes("")
        assertEquals("d41d8cd98f00b204e9800998ecf8427e", hashes.md5)
        assertEquals("da39a3ee5e6b4b0d3255bfef95601890afd80709", hashes.sha1)
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hashes.sha256)
        assertEquals(HashFormat.SHA256, PayloadDecoder.detectHashFormat(hashes.sha256))

        // Unsigned expired JWT should trigger critical warnings
        val header = PayloadDecoder.encodeBase64("""{"alg":"none","typ":"JWT"}""").trimEnd('=')
        val payload = PayloadDecoder.encodeBase64("""{"sub":"analyst","iss":"auth.test","exp":1500000000}""").trimEnd('=')
        val jwtResult = PayloadDecoder.inspectJwt("$header.$payload.").getOrThrow()
        assertEquals("none", jwtResult.algorithm)
        assertEquals("analyst", jwtResult.subject)
        assertEquals(true, jwtResult.isExpired)
        assertTrue(jwtResult.securityWarnings.any { it.contains("Unsigned token") })
        assertTrue(jwtResult.securityWarnings.any { it.contains("Token expired") })
    }

    @Test
    fun testCaseReportExporterEscapingAndGraph() {
        val caseItem = InvestigationCase(
            id = "case-1",
            title = "Phish <script>alert(1)</script>",
            target = "evil.example.com",
            notes = "=HYPERLINK(\"http://bad\")"
        )
        val artifacts = listOf(
            ScanArtifact(
                id = "art-1",
                caseId = "case-1",
                wingType = "DOMAIN_RECON",
                artifactType = "DNS_RECORD",
                queryTarget = "198.51.100.55",
                title = "A Record <b>match</b>",
                summary = "Resolved evil.example.com -> 198.51.100.55 & contact admin@evil.example.com",
                rawJson = "{}",
                sourceApi = "Cloudflare DoH"
            )
        )

        val html = CaseReportExporter.exportHtml(caseItem, artifacts)
        assertFalse(html.contains("<script>alert(1)</script>"))
        assertTrue(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"))

        val json = CaseReportExporter.exportJson(caseItem, artifacts)
        assertTrue(json.contains("\"schema\": \"osintme.dossier.v1\""))
        assertTrue(json.contains("evil.example.com"))

        val csv = CaseReportExporter.exportCsv(caseItem, artifacts)
        assertTrue(csv.contains("case_target,wing,artifact_type"))
        assertTrue(csv.contains("198[.]51[.]100[.]55"))

        val graph = CaseReportExporter.buildEntityGraph(caseItem, artifacts)
        assertTrue(graph.nodes.any { it.isRoot && it.label == "evil.example.com" })
        assertTrue(graph.nodes.any { it.label == "198.51.100.55" })
        assertTrue(graph.edges.isNotEmpty())
    }

    @Test
    fun testWebTechReconFingerprinting() {
        val html = """
            <html>
              <head>
                <title>Acme Corp Portal</title>
                <meta name="generator" content="WordPress 6.5" />
                <script src="https://www.googletagmanager.com/gtag/js?id=G-123"></script>
                <script src="https://cdn.partner-service.io/widget.js"></script>
              </head>
              <body class="bg-slate-900 flex-col">
                <div id="__NEXT_DATA__"></div>
                <img src="/wp-content/uploads/logo.png" />
              </body>
            </html>
        """.trimIndent()
        val headers = mapOf(
            "Server" to "cloudflare",
            "CF-RAY" to "8abc123-BOM"
        )

        val recon = WebTechReconService.analyzeHtmlFingerprint(
            targetHost = "acme.example.com",
            finalUrl = "https://acme.example.com/",
            httpStatus = 200,
            headers = headers,
            html = html
        )

        assertEquals("Acme Corp Portal", recon.pageTitle)
        assertNotNull(recon.technologies.find { it.name == "Cloudflare" })
        assertNotNull(recon.technologies.find { it.name == "Next.js" })
        assertNotNull(recon.technologies.find { it.name == "WordPress" })
        assertNotNull(recon.technologies.find { it.name == "Tailwind CSS" })
        assertTrue(recon.externalDomains.contains("cdn.partner-service.io"))
    }

    @Test
    fun testByokAiEndpointValidationAndResponseParsing() {
        // SSRF / cleartext guardrails
        assertTrue(ByokAiService.validateEndpointUrl("https://openrouter.ai/api/v1/chat/completions").isSuccess)
        assertTrue(ByokAiService.validateEndpointUrl("http://openrouter.ai/api/v1/chat/completions").isFailure)
        assertTrue(ByokAiService.validateEndpointUrl("https://127.0.0.1/v1/chat/completions").isFailure)
        assertTrue(ByokAiService.validateEndpointUrl("https://localhost:8080/v1/chat/completions").isFailure)
        assertTrue(ByokAiService.validateEndpointUrl("https://192.168.1.50/v1/chat/completions").isFailure)

        // OpenAI-compatible protocol parsing
        val openAiJson = """{"choices":[{"message":{"content":"Target domain uses Cloudflare."}}]}"""
        assertEquals(
            "Target domain uses Cloudflare.",
            ByokAiService.parseResponseText(AiProtocol.OPENAI_COMPATIBLE, openAiJson).getOrThrow()
        )

        // Anthropic Messages v1 protocol parsing
        val anthropicJson = """{"content":[{"type":"text","text":"High spoofing risk detected."}]}"""
        assertEquals(
            "High spoofing risk detected.",
            ByokAiService.parseResponseText(AiProtocol.ANTHROPIC_MESSAGES, anthropicJson).getOrThrow()
        )

        // Gemini BYOK REST protocol parsing
        val geminiJson = """{"candidates":[{"content":{"parts":[{"text":"Executive Brief ready."}]}}]}"""
        assertEquals(
            "Executive Brief ready.",
            ByokAiService.parseResponseText(AiProtocol.GEMINI_REST, geminiJson).getOrThrow()
        )

        // AI dork line parser
        val dorks = ByokAiService.parseDorkLines(
            """
            GOOGLE | Exposed Env | site:example.com ext:env | Look for leaked configs
            SHODAN | Open Panels | ssl:"example.com" http.title:"Admin" | Find admin portals
            """.trimIndent()
        )
        assertEquals(2, dorks.size)
        assertEquals("GOOGLE", dorks[0].engine)
        assertEquals("SHODAN", dorks[1].engine)
    }

    @Test
    fun testWaybackCdxParsingAndClassification() {
        val cdxJson = """
            [
              ["timestamp","original","statuscode","mimetype","length"],
              ["20240215120000","https://dev.example.com/.env.backup","200","text/plain","512"],
              ["20231101090000","https://example.com/reports/q4-audit.pdf","200","application/pdf","42000"],
              ["20220105083000","https://old.example.com/removed-article","404","text/html","120"]
            ]
        """.trimIndent()

        val report = WaybackCdxService.parseCdxJson("example.com", cdxJson)
        assertEquals(3, report.snapshots.size)
        assertEquals(1, report.sensitiveCount)
        assertEquals(1, report.documentCount)
        assertEquals(1, report.deletedCount)
        assertTrue(report.discoveredHosts.contains("dev.example.com"))
        assertTrue(report.discoveredHosts.contains("old.example.com"))

        val (catSensitive, _) = WaybackCdxService.classifySnapshot("https://a.com/config.sql", "200", "text/plain")
        assertEquals(WaybackCategory.SENSITIVE, catSensitive)
        val (catDoc, _) = WaybackCdxService.classifySnapshot("https://a.com/deck.pdf", "200", "application/pdf")
        assertEquals(WaybackCategory.DOCUMENT, catDoc)
        val (catDeleted, _) = WaybackCdxService.classifySnapshot("https://a.com/gone", "404", "text/html")
        assertEquals(WaybackCategory.DELETED, catDeleted)
    }

    @Test
    fun testSubdomainTakeoverSignatureMatching() {
        assertEquals("GitHub Pages", TlsAndTakeoverService.matchTakeoverProvider("org.github.io."))
        assertEquals("AWS S3 Bucket", TlsAndTakeoverService.matchTakeoverProvider("assets.s3.amazonaws.com"))
        assertEquals("Heroku", TlsAndTakeoverService.matchTakeoverProvider("app.herokudns.com"))
        assertEquals("Shopify", TlsAndTakeoverService.matchTakeoverProvider("shops.myshopify.com"))
        assertEquals(null, TlsAndTakeoverService.matchTakeoverProvider("www.google.com"))
    }

    @Test
    fun testRedirectHeaderGradingAndCookieAudit() {
        val strongHeaders = mapOf(
            "Strict-Transport-Security" to "max-age=31536000; includeSubDomains",
            "Content-Security-Policy" to "default-src 'self'",
            "X-Frame-Options" to "DENY",
            "X-Content-Type-Options" to "nosniff",
            "Referrer-Policy" to "strict-origin-when-cross-origin",
            "Permissions-Policy" to "geolocation=()"
        )
        val strongGrade = RedirectHeaderService.gradeSecurityHeaders(strongHeaders, isHttps = true)
        assertTrue(strongGrade.score >= 90)
        assertEquals("A+", strongGrade.grade)

        val weakGrade = RedirectHeaderService.gradeSecurityHeaders(
            mapOf("Access-Control-Allow-Origin" to "*"),
            isHttps = false
        )
        assertEquals("F", weakGrade.grade)
        assertNotNull(weakGrade.corsWarning)

        val cookies = RedirectHeaderService.auditSetCookies(
            listOf("session_id=abc123; Path=/", "csrf=xyz; Secure; HttpOnly; SameSite=Strict")
        )
        assertEquals(2, cookies.size)
        assertFalse(cookies[0].hasSecure)
        assertFalse(cookies[0].hasHttpOnly)
        assertTrue(cookies[1].hasSecure)
        assertTrue(cookies[1].hasHttpOnly)
    }

    @Test
    fun testCaseReportHtmlEscapesAiExecutiveBrief() {
        val caseItem = InvestigationCase(id = "case-ai", title = "Audit", target = "example.com")
        val html = CaseReportExporter.exportHtml(
            targetCase = caseItem,
            artifacts = emptyList(),
            aiExecutiveSummary = "Summary <img src=x onerror=alert(1)> safe text"
        )
        assertTrue(html.contains("AI Executive Intelligence Brief"))
        assertFalse(html.contains("<img src=x onerror=alert(1)>"))
        assertTrue(html.contains("&lt;img src=x onerror=alert(1)&gt;"))
    }

    @Test
    fun testAlienVaultOtxParsing() {
        val generalJson = """
            {
              "asn": "AS13335 Cloudflare",
              "country_name": "United States",
              "pulse_info": {
                "count": 2,
                "pulses": [
                  {
                    "name": "Phishing Infrastructure Wave",
                    "created": "2026-10-12T08:00:00",
                    "adversary": "APT-Test",
                    "tags": ["phishing", "credential-harvest"]
                  },
                  {
                    "name": "C2 Beacon Domain",
                    "created": "2026-10-15T12:00:00",
                    "adversary": "",
                    "tags": ["c2"]
                  }
                ]
              }
            }
        """.trimIndent()

        val report = AlienVaultOtxService.parseGeneralJson("evil.test", "DOMAIN", generalJson)
        assertEquals(2, report.pulseCount)
        assertEquals(2, report.pulses.size)
        assertEquals("AS13335 Cloudflare", report.asn)
        assertEquals("APT-Test", report.pulses[0].adversary)
        assertTrue(report.tags.contains("phishing"))
        assertTrue(report.tags.contains("c2"))

        val pdnsJson = """
            {
              "passive_dns": [
                {"hostname": "api.evil.test", "address": "198.51.100.22"},
                {"hostname": "*.wildcard.evil.test", "address": "198.51.100.23"},
                {"hostname": "evil.test", "address": "198.51.100.22"}
              ]
            }
        """.trimIndent()
        val pdns = AlienVaultOtxService.parsePassiveDnsJson(pdnsJson, "evil.test")
        assertTrue(pdns.contains("api.evil.test"))
        assertTrue(pdns.contains("198.51.100.22"))
        assertFalse(pdns.any { it.contains("*") })

        val urlListJson = """
            {
              "url_list": [
                {"url": "https://evil.test/login"},
                {"url": "ftp://ignored.test/file"},
                {"url": "http://evil.test/stage2"}
              ]
            }
        """.trimIndent()
        val urls = AlienVaultOtxService.parseUrlListJson(urlListJson)
        assertEquals(2, urls.size)
        assertTrue(urls.contains("https://evil.test/login"))
        assertTrue(urls.contains("http://evil.test/stage2"))
    }

    @Test
    fun testDeepWebCrawlerExtractionAndSsrfGuard() {
        val html = """
            <html>
              <head>
                <title>Acme Security Portal</title>
                <meta name="description" content="Enterprise threat defense platform" />
                <meta property="og:site_name" content="Acme Corp" />
              </head>
              <body>
                <a href="mailto:secops@acmecorp.io">Contact</a>
                <a href="https://github.com/acmesec">GitHub</a>
                <a href="https://x.com/acmesec_io">X</a>
                <script>
                  gtag('config', 'G-9876543210');
                  fbq('init', '123456789012345');
                </script>
              </body>
            </html>
        """.trimIndent()
        val jsBundle = """
            const apiBase = "/api/v2/investigations/export";
            const bucket = "https://acme-public-assets.s3.amazonaws.com/reports";
            const firebaseDb = "acme-prod-app.firebaseio.com";
            const gtm = "GTM-ABC1234";
            const ads = "ca-pub-1234567890123456";
        """.trimIndent()
        val secTxt = """
            Contact: mailto:security@acmecorp.io
            Policy: https://acmecorp.io/disclosure
        """.trimIndent()
        val sitemap = """
            <urlset>
              <url><loc>https://acmecorp.io/docs</loc></url>
              <url><loc>https://acmecorp.io/status</loc></url>
            </urlset>
        """.trimIndent()

        val report = DeepWebCrawlerService.extractIntelligence(
            targetHost = "acmecorp.io",
            finalUrl = "https://acmecorp.io/",
            html = html,
            jsBundles = listOf(jsBundle),
            securityTxt = secTxt,
            sitemapXml = sitemap
        )

        assertEquals("Acme Security Portal", report.pageTitle)
        assertEquals("Acme Corp", report.metaAuthorOrOrg)
        assertTrue(report.emails.contains("secops@acmecorp.io"))
        assertTrue(report.emails.contains("security@acmecorp.io"))
        assertTrue(report.socialLinks.any { it.platform == "GitHub" && it.handle == "acmesec" })
        assertTrue(report.socialLinks.any { it.platform == "X / Twitter" && it.handle == "acmesec_io" })
        assertTrue(report.trackingIds.any { it.id == "G-9876543210" })
        assertTrue(report.trackingIds.any { it.id == "GTM-ABC1234" })
        assertTrue(report.trackingIds.any { it.id == "ca-pub-1234567890123456" })
        assertTrue(report.apiEndpoints.contains("/api/v2/investigations/export"))
        assertTrue(report.cloudBuckets.any { it.contains("acme-public-assets.s3.amazonaws.com") })
        assertTrue(report.cloudBuckets.any { it.contains("acme-prod-app.firebaseio.com") })
        assertTrue(report.securityTxtContacts.contains("mailto:security@acmecorp.io"))
        assertEquals(2, report.sitemapSampleUrls.size)
        assertEquals(1, report.jsFilesScanned)

        // SSRF / private host blocking
        assertTrue(DeepWebCrawlerService.isPrivateOrUnsafeHost("localhost"))
        assertTrue(DeepWebCrawlerService.isPrivateOrUnsafeHost("127.0.0.1"))
        assertTrue(DeepWebCrawlerService.isPrivateOrUnsafeHost("internal.local"))
    }

    @Test
    fun testEmailAndIdentityIntelParsers() {
        assertEquals(
            "Google Workspace / Gmail",
            EmailAndIdentityIntelService.detectMailProviderSuite(listOf("10 aspmx.l.google.com."))
        )
        assertEquals(
            "Microsoft 365 / Exchange Online",
            EmailAndIdentityIntelService.detectMailProviderSuite(listOf("0 acme-com.mail.protection.outlook.com"))
        )
        assertEquals(
            "Proton Mail",
            EmailAndIdentityIntelService.detectMailProviderSuite(listOf("10 mail.protonmail.ch"))
        )

        val userJson = """
            {
              "login": "torvalds",
              "name": "Linus Torvalds",
              "bio": "Kernel maintainer",
              "company": "Linux Foundation",
              "location": "Portland, OR",
              "blog": "https://kernel.org",
              "twitter_username": null,
              "public_repos": 12,
              "followers": 210000,
              "created_at": "2011-09-03T15:26:22Z",
              "html_url": "https://github.com/torvalds"
            }
        """.trimIndent()
        val eventsJson = """
            [
              {
                "payload": {
                  "commits": [
                    {"author": {"name": "Linus Torvalds", "email": "torvalds@linux-foundation.org"}},
                    {"author": {"name": "Bot", "email": "12345+torvalds@users.noreply.github.com"}}
                  ]
                }
              }
            ]
        """.trimIndent()
        val orgsJson = """[{"login": "linux-foundation"}]"""

        val gh = EmailAndIdentityIntelService.parseGithubDeepJson(userJson, eventsJson, orgsJson)
        assertEquals("torvalds", gh.username)
        assertEquals("Linus Torvalds", gh.displayName)
        assertTrue(gh.commitEmails.contains("torvalds@linux-foundation.org"))
        assertFalse(gh.commitEmails.any { it.contains("users.noreply.github.com") })
        assertTrue(gh.organizations.contains("linux-foundation"))

        val keybaseJson = """
            {
              "them": [
                {
                  "basics": {"username": "alice_sec"},
                  "profile": {"full_name": "Alice Analyst", "bio": "OSINT researcher", "location": "London"},
                  "public_keys": {"primary": {"key_fingerprint": "AABBCCDD11223344"}},
                  "proofs_summary": {
                    "all": [
                      {"proof_type": "github", "nametag": "alicesec"},
                      {"proof_type": "dns", "nametag": "alice.security"}
                    ]
                  }
                }
              ]
            }
        """.trimIndent()
        val kb = EmailAndIdentityIntelService.parseKeybaseJson(keybaseJson)
        assertNotNull(kb)
        assertEquals("alice_sec", kb!!.username)
        assertEquals("AABBCCDD11223344", kb.pgpFingerprint)
        assertEquals(2, kb.verifiedProofs.size)
    }

    @Test
    fun testNetworkSecurityGuardAndSafeBrowserLauncher() {
        // Blocked private, loopback, link-local, metadata, CGNAT, and IPv6 local hosts
        val blockedHosts = listOf(
            "localhost",
            "sub.localhost",
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "::1",
            "fc00::1",
            "fe80::1",
            "metadata.google.internal",
            "printer.local"
        )
        blockedHosts.forEach { host ->
            assertTrue("Expected $host to be blocked", NetworkSecurityGuard.isBlockedPrivateHost(host))
        }

        // Public hosts allowed by literal check
        assertFalse(NetworkSecurityGuard.isBlockedPrivateHost("1.1.1.1"))
        assertFalse(NetworkSecurityGuard.isBlockedPrivateHost("8.8.8.8"))

        // Public HTTPS URL validation & strict requireHttps enforcement
        assertTrue(NetworkSecurityGuard.validatePublicHttpUrl("https://1.1.1.1/dns-query", requireHttps = true).isSuccess)
        assertTrue(NetworkSecurityGuard.validatePublicHttpUrl("http://1.1.1.1/dns-query", requireHttps = true).isFailure)
        assertTrue(NetworkSecurityGuard.validatePublicHttpUrl("file:///etc/passwd", requireHttps = false).isFailure)
        assertTrue(NetworkSecurityGuard.validatePublicHttpUrl("javascript:alert(1)", requireHttps = false).isFailure)
        assertTrue(NetworkSecurityGuard.validatePublicHttpUrl("https://1.1.1.1/a\r\nb", requireHttps = true).isFailure)
        assertTrue(NetworkSecurityGuard.validatePublicHttpUrl("https://169.254.169.254/latest/meta-data/", requireHttps = true).isFailure)
        assertTrue(NetworkSecurityGuard.validatePublicHttpUrl("http://127.0.0.1:8080/admin", requireHttps = false).isFailure)

        // External browser launcher validation (only public http/https allowed)
        assertEquals("https://1.1.1.1/help", SafeBrowserLauncher.validateExternalWebUrl("https://1.1.1.1/help"))
        assertNull(SafeBrowserLauncher.validateExternalWebUrl("intent://scan/#Intent;scheme=zxing;end"))
        assertNull(SafeBrowserLauncher.validateExternalWebUrl("file:///data/local/tmp/test"))
        assertNull(SafeBrowserLauncher.validateExternalWebUrl("content://com.oopssecurity.osintme.fileprovider/clean_images/a.jpg"))
        assertNull(SafeBrowserLauncher.validateExternalWebUrl("javascript:alert(1)"))
        assertNull(SafeBrowserLauncher.validateExternalWebUrl("http://127.0.0.1/admin"))
        assertNull(SafeBrowserLauncher.validateExternalWebUrl("https://192.168.1.1/router"))
    }
}
