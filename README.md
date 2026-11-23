# OSINTme 🛡️
> **By Oops Security** (`com.oopssecurity.osintme`)  
> Professional Tactical Reconnaissance, Digital Footprint & Privacy Audit Suite for Android.

Built with **Kotlin + Jetpack Compose** using modern architectural principles (Material 3, Navigation3, Coroutines, OkHttp, Zero-Cloud Local Privacy).

---

## 🎯 Core Capabilities & Wings

### 🌐 Wing 01 // Network & Infrastructure Intelligence
- **Shodan Host & Port Intel:** Live Shodan InternetDB query engine. Resolves domains to IPv4 and inspects open ports, CVEs, CPEs, and active services.
- **GeoIP & ASN Telemetry:** Direct IP-API integration for ISP, ASN, Organization, City, Country, and geographic coordinates.
- **Subdomain Discovery (Dual-Engine):**
  - Primary: HackerTarget HostSearch API (rapid passive subdomain enumeration).
  - Secondary: `crt.sh` Certificate Transparency log analysis.
- **Cloudflare DNS-over-HTTPS (DoH):** Direct encrypted queries to `1.1.1.1` for `A`, `AAAA`, `MX`, `TXT`, `NS` records with TTL metadata.
- **WHOIS / RDAP:** Real registry information, registration dates, expiration timestamps, and nameservers.
- **Wayback Machine CDX Engine:** Scans Internet Archive CDX endpoints for historical paths, sensitive files (`.env`, `.sql`, `.bak`, `.php`), and archived snapshots.

### 🔐 Wing 02 // Identity & Compromise Intelligence
- **Public Breach Auditor:** Real-time query to XposedOrNot breach database & breach analytics to identify leaked services and exposed data types.
- **Password Leak Auditor (k-Anonymity):** Zero-knowledge local SHA-1 hashing. Raw passwords never leave the device; only the 5-character prefix is checked against HaveIBeenPwned.

### 👥 Wing 03 // Social & Telephony Intelligence
- **Multi-Platform Username Hunter:** High-concurrency probing across 38+ platforms (GitHub, GitLab, DockerHub, Dev.to, Reddit, Gravatar, Chess.com, HackerNews, Keybase, Codeforces, etc.) with body-signature matching to eliminate false positives.
- **Phone Number Recon & Operational Pivots:**
  - 38+ country E.164 normalization, ITU dial code mapping, and national format parsing.
  - Carrier heuristics & line type identification (Cellular, VoIP, Fixed line).
  - Direct 1-tap pivots: WhatsApp Click-to-Chat (`wa.me`), Telegram profile (`t.me`), Truecaller directory search, and Google Dork leak queries.

### 🔍 Wing 04 // Digital Forensics & Privacy Tools
- **EXIF Forensics & Stripper (100% Offline):** Extracts camera model, software, exposure settings, and GPS coordinates. Includes a 1-tap "Strip & Share Clean Image" engine via Android FileProvider.
- **Google Dorks Generator:** 8 weaponized presets for exposed docs, login pages, cloud storage buckets, SQL dumps, environment files (`.env`), and directory indexes.
- **Link & Tracker Sanitizer:** Strips 60+ invasive marketing parameters (`utm_*`, `si`, `igsh`, `fbclid`, `gclid`, `ref`, `trk`) from shared URLs.
- **Digital Exposure Score & Hygiene Checklist:** 7-point threat hygiene evaluation card.

---

## 🎨 UI & Design System
- **Design Philosophy:** Linear / Raycast / Proton Cyber Utility style (Zero cliché neon/Matrix tropes).
- **OLED Precision Dark Palette:**
  - Background: `#060709` (Pitch Obsidian)
  - Elevated Surfaces: `#0D1017` (Deep Carbon Navy)
  - Borders: `#1C2333` (Subtle 1dp Razor Borders)
  - Primary Accent: `#00F0FF` (Electric Sky Cyan)
  - Secondary Accent: `#00E676` (Matrix / Safe Green)
  - Badges & Tags: `#818CF8` (Soft Indigo)

---

## 🔒 Privacy & Architecture
- **Zero-Cloud Personal Storage:** All scan dossiers and history are saved strictly on the user's local device.
- **System Share Sheet Integration:** Share images or URLs directly from any Android app into OSINTme to strip EXIF or clean tracking links.
- **Monetization Architecture:** AppLovin MAX / LevelPlay mediation with privacy-safe banner placement and contextual partner security recommendations (via Supabase REST).

---

## 🛠️ Build & Run
- **JDK:** OpenJDK 21 LTS
- **Gradle:** 9.6
- **Android SDK:** Compile SDK 36, Target SDK 35, Min SDK 26

```bash
# Assemble Debug APK
./gradlew assembleDebug

# Install via ADB
adb install -r app/build/outputs/apk/debug/app-debug.apk
```
