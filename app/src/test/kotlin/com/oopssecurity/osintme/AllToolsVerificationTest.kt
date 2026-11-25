package com.oopssecurity.osintme

import com.oopssecurity.osintme.data.local.ActiveAiConfig
import com.oopssecurity.osintme.data.local.AiProtocol
import com.oopssecurity.osintme.data.local.AiProvider
import com.oopssecurity.osintme.data.local.CUSTOM_ENDPOINT_PRESETS
import com.oopssecurity.osintme.data.model.InvestigationCase
import com.oopssecurity.osintme.data.model.ScanArtifact
import com.oopssecurity.osintme.data.network.AiChatMessage
import com.oopssecurity.osintme.data.network.AlienVaultOtxService
import com.oopssecurity.osintme.data.network.BgpAsnService
import com.oopssecurity.osintme.data.network.ByokAiService
import com.oopssecurity.osintme.data.network.CrtShService
import com.oopssecurity.osintme.data.network.DeepWebCrawlerService
import com.oopssecurity.osintme.data.network.EmailAndIdentityIntelService
import com.oopssecurity.osintme.data.network.GravatarService
import com.oopssecurity.osintme.data.network.HibpPasswordService
import com.oopssecurity.osintme.data.network.OpsecManager
import com.oopssecurity.osintme.data.network.PhoneReconService
import com.oopssecurity.osintme.data.network.PlatformReconService
import com.oopssecurity.osintme.data.network.ProThreatApiServices
import com.oopssecurity.osintme.data.network.RedirectHeaderService
import com.oopssecurity.osintme.data.network.RedirectResolverService
import com.oopssecurity.osintme.data.network.TlsAndTakeoverService
import com.oopssecurity.osintme.data.network.TlsHeaderAuditService
import com.oopssecurity.osintme.data.network.WaybackCdxService
import com.oopssecurity.osintme.data.network.WaybackService
import com.oopssecurity.osintme.data.network.WebTechReconService
import com.oopssecurity.osintme.ui.dorks.DorkViewModel
import com.oopssecurity.osintme.ui.dorks.SearchEngineTarget
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
import com.oopssecurity.osintme.util.ReverseImageService
import com.oopssecurity.osintme.util.SafeBrowserLauncher
import com.oopssecurity.osintme.util.UrlSanitizer
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Comprehensive verification suite covering every OSINT tool, engine, parser,
 * security guardrail, and BYOK AI custom-endpoint workflow in OSINTme.
 */
class AllToolsVerificationTest {

    // -------------------------------------------------------------------------
    // 1. BYOK AI Setup & Custom Endpoint Support (All Providers & Protocols)
    // -------------------------------------------------------------------------

    @Test
    fun testAiProvidersOrderPresetsAndDefaultEndpoints() {
        // Custom OpenAI-Compatible must be immediately discoverable near the top
        assertEquals(AiProvider.OPENROUTER, AiProvider.entries[0])
        assertEquals(AiProvider.CUSTOM_OPENAI, AiProvider.entries[1])
        assertEquals(10, AiProvider.entries.size)

        // Every provider's default endpoint must pass strict HTTPS + public host validation
        AiProvider.entries.forEach { provider ->
            val validated = ByokAiService.validateEndpointUrl(provider.defaultBaseUrl, provider.protocol)
            assertTrue(
                "Default URL for ${provider.displayName} failed validation: ${validated.exceptionOrNull()?.message}",
                validated.isSuccess
            )
            assertTrue("Default model missing for ${provider.displayName}", provider.defaultModel.isNotBlank())
            assertTrue("Docs URL must be safe HTTPS for ${provider.displayName}", SafeBrowserLauncher.validateExternalWebUrl(provider.docsUrl) != null)
        }

        // Every one-tap custom endpoint preset must be valid HTTPS with non-blank model
        assertTrue(CUSTOM_ENDPOINT_PRESETS.size >= 5)
        CUSTOM_ENDPOINT_PRESETS.forEach { preset ->
            val res = ByokAiService.validateEndpointUrl(preset.endpointUrl, AiProtocol.OPENAI_COMPATIBLE)
            assertTrue("Preset ${preset.label} invalid: ${res.exceptionOrNull()?.message}", res.isSuccess)
            assertTrue(preset.defaultModel.isNotBlank())
            assertTrue(preset.label.isNotBlank())
        }
    }

    @Test
    fun testCustomEndpointNormalizationAcrossAllThreeProtocols() {
        // OpenAI-compatible base URLs & gateways auto-complete to /chat/completions
        assertEquals(
            "https://gateway.example.com/v1/chat/completions",
            ByokAiService.normalizeEndpointUrl(AiProtocol.OPENAI_COMPATIBLE, "https://gateway.example.com")
        )
        assertEquals(
            "https://api.together.xyz/v1/chat/completions",
            ByokAiService.normalizeEndpointUrl(AiProtocol.OPENAI_COMPATIBLE, "https://api.together.xyz/v1/")
        )
        assertEquals(
            "https://api.groq.com/openai/v1/chat/completions",
            ByokAiService.normalizeEndpointUrl(AiProtocol.OPENAI_COMPATIBLE, "https://api.groq.com/openai/v1")
        )
        assertEquals(
            "https://openrouter.ai/api/v1/chat/completions",
            ByokAiService.normalizeEndpointUrl(AiProtocol.OPENAI_COMPATIBLE, "https://openrouter.ai/api/v1")
        )
        // Already-complete or non-standard custom proxy paths are preserved verbatim
        assertEquals(
            "https://proxy.corp.org/custom/llm-route",
            ByokAiService.normalizeEndpointUrl(AiProtocol.OPENAI_COMPATIBLE, "https://proxy.corp.org/custom/llm-route")
        )
        assertEquals(
            "https://api.openai.com/v1/chat/completions",
            ByokAiService.normalizeEndpointUrl(AiProtocol.OPENAI_COMPATIBLE, "https://api.openai.com/v1/chat/completions")
        )

        // Anthropic Messages API custom gateways
        assertEquals(
            "https://claude-proxy.example.com/v1/messages",
            ByokAiService.normalizeEndpointUrl(AiProtocol.ANTHROPIC_MESSAGES, "https://claude-proxy.example.com")
        )
        assertEquals(
            "https://claude-proxy.example.com/v1/messages",
            ByokAiService.normalizeEndpointUrl(AiProtocol.ANTHROPIC_MESSAGES, "https://claude-proxy.example.com/v1")
        )
        assertEquals(
            "https://api.anthropic.com/v1/messages",
            ByokAiService.normalizeEndpointUrl(AiProtocol.ANTHROPIC_MESSAGES, "https://api.anthropic.com/v1/messages")
        )

        // Gemini REST custom gateways
        assertEquals(
            "https://gemini-gw.example.com/v1beta/models",
            ByokAiService.normalizeEndpointUrl(AiProtocol.GEMINI_REST, "https://gemini-gw.example.com")
        )
        assertEquals(
            "https://gemini-gw.example.com/v1beta/models",
            ByokAiService.normalizeEndpointUrl(AiProtocol.GEMINI_REST, "https://gemini-gw.example.com/v1beta/")
        )
        assertEquals(
            "https://gemini-gw.example.com/v1/models",
            ByokAiService.normalizeEndpointUrl(AiProtocol.GEMINI_REST, "https://gemini-gw.example.com/v1")
        )
        // Explicit :generateContent URL preserved
        val explicitGemini = "https://gemini-gw.example.com/v1beta/models/gemini-2.5-flash:generateContent"
        assertEquals(
            explicitGemini,
            ByokAiService.normalizeEndpointUrl(AiProtocol.GEMINI_REST, explicitGemini)
        )
    }

    @Test
    fun testCustomEndpointRequestBuildersAndSecurityGuardrails() {
        val sampleMsgs = listOf(AiChatMessage("user", "Analyze example.com"))

        // 1. Custom OpenAI-Compatible request
        val customUrl = ByokAiService.validateEndpointUrl("https://api.together.xyz/v1", AiProtocol.OPENAI_COMPATIBLE).getOrThrow()
        val openAiReq = ByokAiService.buildRequestForConfig(
            config = ActiveAiConfig(AiProvider.CUSTOM_OPENAI, "sk-test-123", "meta-llama/Llama-3.3-70B-Instruct-Turbo", customUrl),
            validatedUrl = customUrl,
            systemPrompt = "System",
            messages = sampleMsgs,
            maxTokens = 256
        )
        assertEquals("https://api.together.xyz/v1/chat/completions", openAiReq.url.toString())
        assertEquals("Bearer sk-test-123", openAiReq.header("Authorization"))

        // 2. Anthropic via custom proxy endpoint
        val claudeUrl = ByokAiService.validateEndpointUrl("https://api.anthropic.com/v1", AiProtocol.ANTHROPIC_MESSAGES).getOrThrow()
        val claudeReq = ByokAiService.buildRequestForConfig(
            config = ActiveAiConfig(AiProvider.ANTHROPIC_CLAUDE, "sk-ant-test", "claude-3-5-haiku-latest", claudeUrl),
            validatedUrl = claudeUrl,
            systemPrompt = "System",
            messages = sampleMsgs,
            maxTokens = 256
        )
        assertEquals("https://api.anthropic.com/v1/messages", claudeReq.url.toString())
        assertEquals("sk-ant-test", claudeReq.header("x-api-key"))
        assertEquals("2023-06-01", claudeReq.header("anthropic-version"))

        // 3. Gemini via custom base URL and via explicit :generateContent URL
        val geminiBase = ByokAiService.validateEndpointUrl("https://generativelanguage.googleapis.com/v1beta", AiProtocol.GEMINI_REST).getOrThrow()
        val geminiReq = ByokAiService.buildRequestForConfig(
            config = ActiveAiConfig(AiProvider.GEMINI_BYOK, "AIza-test", "gemini-2.5-flash", geminiBase),
            validatedUrl = geminiBase,
            systemPrompt = "System",
            messages = sampleMsgs,
            maxTokens = 256
        )
        assertEquals(
            "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent",
            geminiReq.url.toString()
        )
        assertEquals("AIza-test", geminiReq.header("x-goog-api-key"))

        val explicitGemini = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-pro:generateContent"
        val geminiExplicitReq = ByokAiService.buildRequestForConfig(
            config = ActiveAiConfig(AiProvider.GEMINI_BYOK, "AIza-test", "gemini-2.5-pro", explicitGemini),
            validatedUrl = explicitGemini,
            systemPrompt = "System",
            messages = sampleMsgs,
            maxTokens = 256
        )
        assertEquals(explicitGemini, geminiExplicitReq.url.toString())

        // 4. Reject insecure / private / SSRF endpoints for EVERY protocol
        val badUrls = listOf(
            "http://api.openai.com/v1/chat/completions",
            "https://127.0.0.1/v1",
            "https://localhost:11434/v1",
            "https://169.254.169.254/latest/meta-data/",
            "https://192.168.0.10/v1",
            "https://10.0.0.5/v1",
            "https://[::1]/v1",
            "ftp://api.example.com/v1",
            ""
        )
        AiProtocol.entries.forEach { proto ->
            badUrls.forEach { bad ->
                assertTrue(
                    "Expected $bad to fail for $proto",
                    ByokAiService.validateEndpointUrl(bad, proto).isFailure
                )
            }
        }

        // 5. Empty or broken AI response JSON returns failure cleanly
        assertTrue(ByokAiService.parseResponseText(AiProtocol.OPENAI_COMPATIBLE, "{}").isFailure)
        assertTrue(ByokAiService.parseResponseText(AiProtocol.ANTHROPIC_MESSAGES, "not-json").isFailure)
        assertTrue(ByokAiService.parseResponseText(AiProtocol.GEMINI_REST, """{"candidates":[]}""").isFailure)
    }

    // -------------------------------------------------------------------------
    // 2. Multi-Engine Dork Generator
    // -------------------------------------------------------------------------

    @Test
    fun testDorkGeneratorAllEnginesAndSafeLaunchUrls() {
        val vm = DorkViewModel()
        vm.setTarget("https://www.Example.ORG/login?next=1")
        assertEquals("Example.ORG", vm.uiState.value.target)

        // Check ALL engines
        val allDorks = vm.uiState.value.dorks
        assertTrue("Expected at least 15 multi-engine dorks", allDorks.size >= 15)

        // Check every individual engine filter
        SearchEngineTarget.entries.filter { it != SearchEngineTarget.ALL }.forEach { engine ->
            vm.selectEngine(engine)
            val filtered = vm.uiState.value.dorks
            assertTrue("Engine ${engine.name} should have at least 1 dork", filtered.isNotEmpty())
            filtered.forEach { item ->
                assertEquals(engine, item.engine)
                assertTrue("Query should reference target", item.formattedQuery.contains("Example.ORG"))
                assertNotNull(
                    "Launch URL must pass SafeBrowserLauncher validation: ${item.launchUrl}",
                    SafeBrowserLauncher.validateExternalWebUrl(item.launchUrl)
                )
            }
        }
    }

    // -------------------------------------------------------------------------
    // 3. Username Hunter (100+ Platforms Catalog Integrity)
    // -------------------------------------------------------------------------

    @Test
    fun testUsernameHunterAllPlatformTemplatesAreSafeHttps() {
        val platforms = PlatformReconService.ALL_PLATFORMS
        assertTrue("Expected >= 100 platforms", platforms.size >= 100)

        platforms.forEach { p ->
            assertTrue("${p.name} checkUrlTemplate must be HTTPS", p.checkUrlTemplate.startsWith("https://"))
            assertTrue("${p.name} profileUrlTemplate must be HTTPS", p.profileUrlTemplate.startsWith("https://"))
            assertTrue("${p.name} checkUrlTemplate must contain %s", p.checkUrlTemplate.contains("%s"))
            assertTrue("${p.name} profileUrlTemplate must contain %s", p.profileUrlTemplate.contains("%s"))
            val formattedCheck = String.format(p.checkUrlTemplate, "octocat")
            val formattedProfile = String.format(p.profileUrlTemplate, "octocat")
            assertNotNull("Invalid check URL for ${p.name}: $formattedCheck", SafeBrowserLauncher.validateExternalWebUrl(formattedCheck))
            assertNotNull("Invalid profile URL for ${p.name}: $formattedProfile", SafeBrowserLauncher.validateExternalWebUrl(formattedProfile))
        }
    }

    // -------------------------------------------------------------------------
    // 4. Reverse Image Search
    // -------------------------------------------------------------------------

    @Test
    fun testReverseImageAllFourSearchEngines() {
        val sampleImg = "https://example.org/assets/photo 1.jpg?size=large&v=2"
        ReverseImageService.SearchEngine.entries.forEach { engine ->
            val url = ReverseImageService.buildSearchUrl(engine, sampleImg)
            assertTrue("Engine ${engine.name} URL must be HTTPS", url.startsWith("https://"))
            assertFalse("Raw unencoded space not allowed in $url", url.contains(" "))
            assertNotNull(
                "Reverse image URL failed SafeBrowserLauncher check: $url",
                SafeBrowserLauncher.validateExternalWebUrl(url)
            )
        }
    }

    // -------------------------------------------------------------------------
    // 5. Network Tool SSRF / Private-Host Guards (No External Calls Needed)
    // -------------------------------------------------------------------------

    @Test
    fun testAllNetworkReconServicesBlockPrivateAndInvalidTargets() = runTest {
        assertTrue(TlsHeaderAuditService.inspectTarget("127.0.0.1").isFailure)
        assertTrue(TlsHeaderAuditService.inspectTarget("localhost").isFailure)
        assertTrue(TlsHeaderAuditService.inspectTarget("").isFailure)

        assertTrue(TlsAndTakeoverService.inspectTlsCertificate("192.168.1.1").isFailure)
        assertTrue(TlsAndTakeoverService.scanSubdomainTakeovers("metadata.google.internal").isFailure)

        assertTrue(RedirectResolverService.traceRedirects("http://127.0.0.1:8080/admin").isFailure)
        assertTrue(RedirectResolverService.traceRedirects("file:///etc/passwd").isFailure)

        assertTrue(RedirectHeaderService.traceAndAudit("http://169.254.169.254/latest/meta-data/").isFailure)

        assertTrue(BgpAsnService.lookupIpOrHost("127.0.0.1").isFailure)
        assertTrue(BgpAsnService.lookupIpOrHost("10.0.0.1").isFailure)
        assertTrue(BgpAsnService.lookupIpOrHost("").isFailure)

        assertTrue(CrtShService.findSubdomains("localhost").isFailure)
        assertTrue(CrtShService.findSubdomains("127.0.0.1").isFailure)
        assertTrue(CrtShService.findSubdomains("").isFailure)

        assertTrue(WaybackService.fetchArchivedUrls("192.168.1.1").isFailure)
        assertTrue(WaybackService.fetchArchivedUrls("").isFailure)

        assertTrue(DeepWebCrawlerService.crawlTarget("127.0.0.1").isFailure)
        assertTrue(WebTechReconService.inspectHost("10.1.2.3").isFailure)

        // Safe graceful responses for blank password & invalid email
        val emptyPw = HibpPasswordService.checkPassword("").getOrThrow()
        assertFalse(emptyPw.isLeaked)
        assertEquals(0L, emptyPw.leakCount)

        val badGravatar = GravatarService.lookupProfile("not-an-email").getOrThrow()
        assertNull(badGravatar)

        // Pro Threat APIs without keys configured in JVM fail cleanly (no crash)
        assertTrue(ProThreatApiServices.lookupVirusTotalDomain("example.com").isFailure)
        assertTrue(ProThreatApiServices.lookupAbuseIpdb("1.1.1.1").isFailure)
        assertTrue(ProThreatApiServices.submitUrlScanLive("https://example.com").isFailure)
    }

    // -------------------------------------------------------------------------
    // 6. Takeover Signatures, Security Headers, Wayback CDX & OTX Edge Cases
    // -------------------------------------------------------------------------

    @Test
    fun testTakeoverHeadersWaybackAndOtxEdgeCases() {
        // Subdomain takeover provider detection
        assertEquals("GitHub Pages", TlsAndTakeoverService.matchTakeoverProvider("docs.github.io"))
        assertEquals("AWS S3 Bucket", TlsAndTakeoverService.matchTakeoverProvider("static.s3-website-us-east-1.amazonaws.com"))
        assertEquals("Heroku", TlsAndTakeoverService.matchTakeoverProvider("staging.herokuapp.com"))
        assertEquals("Microsoft Azure", TlsAndTakeoverService.matchTakeoverProvider("portal.azurewebsites.net"))
        assertEquals("Fastly", TlsAndTakeoverService.matchTakeoverProvider("cdn.fastly.net"))
        assertNull(TlsAndTakeoverService.matchTakeoverProvider("mail.cloudflare.com"))

        // RedirectHeaderService mid-tier grades
        val midHeaders = mapOf(
            "Strict-Transport-Security" to "max-age=31536000",
            "X-Content-Type-Options" to "nosniff",
            "X-Frame-Options" to "SAMEORIGIN"
        )
        val midGrade = RedirectHeaderService.gradeSecurityHeaders(midHeaders, isHttps = true)
        assertTrue("Expected score in mid range, got ${midGrade.score}", midGrade.score in 30..85)
        assertNull(midGrade.corsWarning)

        // Wayback CDX malformed / empty resilience
        val emptyCdx = WaybackCdxService.parseCdxJson("example.com", "[]")
        assertEquals(0, emptyCdx.snapshots.size)
        val headerOnlyCdx = WaybackCdxService.parseCdxJson("example.com", """[["timestamp","original","statuscode","mimetype","length"]]""")
        assertEquals(0, headerOnlyCdx.snapshots.size)

        // OTX malformed / minimal JSON resilience
        val emptyOtx = AlienVaultOtxService.parseGeneralJson("clean.example", "DOMAIN", "{}")
        assertEquals(0, emptyOtx.pulseCount)
        assertTrue(emptyOtx.pulses.isEmpty())
        assertTrue(AlienVaultOtxService.parsePassiveDnsJson("{}", "clean.example").isEmpty())
        assertTrue(AlienVaultOtxService.parseUrlListJson("{}").isEmpty())
    }

    // -------------------------------------------------------------------------
    // 7. Email Forensics, Phone Recon, Link Sanitizer, Payload Lab & IOCs
    // -------------------------------------------------------------------------

    @Test
    fun testEmailForensicsCleanAndEmptyInputs() {
        val cleanHeaders = """
            Return-Path: <noreply@example.com>
            Received: from mail.example.com ([198.51.100.12])
                by mx.recipient.org with ESMTPS; Tue, 10 Nov 2026 10:00:05 +0000
            Authentication-Results: mx.recipient.org;
                spf=pass smtp.mailfrom=example.com;
                dkim=pass header.i=@example.com;
                dmarc=pass action=none header.from=example.com
            From: Example Notifications <noreply@example.com>
            Subject: Monthly Receipt
        """.trimIndent()
        val cleanReport = EmailHeaderAnalyzer.analyze(cleanHeaders)
        assertEquals("example.com", cleanReport.fromDomain)
        assertEquals("LOW", cleanReport.riskVerdict)
        assertTrue(cleanReport.spoofingAlerts.isEmpty())

        val emptyReport = EmailHeaderAnalyzer.analyze("")
        assertEquals(0, emptyReport.hops.size)
    }

    @Test
    fun testPhoneReconMultiCountryCoverage() {
        val uk = PhoneReconService.analyzeNumber("+44 7700 900077").getOrThrow()
        assertEquals("+44", uk.dialCode)
        assertTrue(uk.isValidLength)

        val de = PhoneReconService.analyzeNumber("+49 30 901820").getOrThrow()
        assertEquals("+49", de.dialCode)
        assertTrue(de.isValidLength)

        val jp = PhoneReconService.analyzeNumber("+81 90-1234-5678").getOrThrow()
        assertEquals("+81", jp.dialCode)
        assertTrue(jp.isValidLength)

        assertTrue(PhoneReconService.analyzeNumber("abc").isFailure)
        assertTrue(PhoneReconService.analyzeNumber("").isFailure)
    }

    @Test
    fun testUrlSanitizerPayloadLabAndCryptoUtilities() {
        // Clean URL keeps all functional query parameters
        val cleanUrl = "https://docs.example.org/search?q=osint&page=2"
        val cleanRes = UrlSanitizer.sanitize(cleanUrl)
        assertTrue(cleanRes.removedParams.isEmpty())
        assertTrue(cleanRes.sanitizedUrl.contains("q=osint"))
        assertTrue(cleanRes.sanitizedUrl.contains("page=2"))

        // CryptoUtil MD5 & SHA-1 known vectors + PayloadDecoder SHA-256
        assertEquals("d41d8cd98f00b204e9800998ecf8427e", CryptoUtil.md5(""))
        assertEquals("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709", CryptoUtil.sha1(""))
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", PayloadDecoder.computeHashes("").sha256)

        // PayloadDecoder URL encode/decode + Epoch decode + invalid input handling
        val urlEncoded = PayloadDecoder.encodeUrl("site:example.com filetype:pdf")
        assertEquals("site:example.com filetype:pdf", PayloadDecoder.decodeUrl(urlEncoded).getOrThrow())
        assertTrue(PayloadDecoder.decodeEpoch("1700000000").getOrThrow().contains("2023-11-14"))
        assertTrue(PayloadDecoder.decodeEpoch("not-a-timestamp").isFailure)
        assertTrue(PayloadDecoder.decodeHex("ZZZZ").isFailure)
        assertTrue(PayloadDecoder.inspectJwt("not-a-jwt").isFailure)
        assertEquals(HashFormat.MD5, PayloadDecoder.detectHashFormat("d41d8cd98f00b204e9800998ecf8427e"))
        assertEquals(HashFormat.SHA1, PayloadDecoder.detectHashFormat("da39a3ee5e6b4b0d3255bfef95601890afd80709"))
        assertEquals(HashFormat.UNKNOWN, PayloadDecoder.detectHashFormat("hello"))

        // Mail provider suite additional providers
        assertTrue(EmailAndIdentityIntelService.detectMailProviderSuite(listOf("10 mx.zoho.com")).contains("Zoho", ignoreCase = true))
        assertTrue(EmailAndIdentityIntelService.detectMailProviderSuite(emptyList()).isNotBlank())
    }

    // -------------------------------------------------------------------------
    // 8. Input Classifier, Pivot Engine, Case Exporter & OPSEC Defaults
    // -------------------------------------------------------------------------

    @Test
    fun testAllPivotTypesClassifierAndOpsecDefaults() {
        // Every PivotEntityType must produce actionable module pivots
        val samples = mapOf(
            PivotEntityType.DOMAIN to "example.com",
            PivotEntityType.IP_ADDRESS to "1.1.1.1",
            PivotEntityType.EMAIL to "analyst@example.com",
            PivotEntityType.USERNAME to "octocat",
            PivotEntityType.URL to "https://example.com/path",
            PivotEntityType.HASH to "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            PivotEntityType.PHONE to "+14155550199"
        )
        samples.forEach { (type, value) ->
            val entity = PivotEngine.normalize(value, type)
            val actions = PivotEngine.buildActions(entity)
            assertTrue("Expected pivot actions for $type", actions.isNotEmpty())
        }

        // Input classifier phone & URL coverage
        assertEquals(InputType.PHONE_NUMBER, InputClassifier.classify("+1 415 555 0199"))
        assertEquals(InputType.TRACKING_URL, InputClassifier.classify("https://news.example.com/a?fbclid=123"))

        // IOC Extractor JSON export contains extracted categories
        val iocRes = IocExtractor.extract("IP 8.8.8.8 contacted https://demo.example.org and md5 d41d8cd98f00b204e9800998ecf8427e")
        assertTrue(iocRes.items.any { it.category == IocCategory.IPV4 })
        assertTrue(iocRes.items.any { it.category == IocCategory.MD5 })
        val iocJson = IocExtractor.toJson(iocRes.items, defanged = true)
        assertTrue(iocJson.contains("8[.]8[.]8[.]8"))

        // Case Exporter graph deduplication
        val c = InvestigationCase(id = "c2", title = "Graph Test", target = "target.io")
        val arts = listOf(
            ScanArtifact("a1", "c2", "DOMAIN", "DNS", "1.1.1.1", "A", "1.1.1.1", "{}", "DoH"),
            ScanArtifact("a2", "c2", "DOMAIN", "DNS", "1.1.1.1", "A dup", "1.1.1.1", "{}", "DoH")
        )
        val graph = CaseReportExporter.buildEntityGraph(c, arts)
        assertEquals(1, graph.nodes.count { it.label == "1.1.1.1" })

        // OPSEC Screen Shield must default to OFF so streamed emulator previews are never blanked
        assertFalse(OpsecManager.screenShieldEnabled)
        assertFalse(OpsecManager.screenShieldEnabledFlow.value)
    }
}
