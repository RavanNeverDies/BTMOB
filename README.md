# Customer Support.apk - Malware Analysis Report

> **DISCLAIMER**: This repository contains a LIVE MALWARE SAMPLE for research and educational purposes ONLY. Do NOT install this APK on any real device. Handle with extreme caution in an isolated sandboxed environment.

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [APK Metadata & Hashes](#apk-metadata--hashes)
3. [Malware Classification](#malware-classification)
4. [How It Works - Infection Lifecycle](#how-it-works---infection-lifecycle)
5. [C2 (Command & Control) Server Infrastructure](#c2-command--control-server-infrastructure)
6. [Permissions Analysis](#permissions-analysis)
7. [Component Architecture](#component-architecture)
8. [Capabilities & System Impact](#capabilities--system-impact)
9. [Persistence Mechanisms](#persistence-mechanisms)
10. [Operator / Server-Side Control](#operator--server-side-control)
11. [Anti-Analysis & Evasion Techniques](#anti-analysis--evasion-techniques)
12. [Network Communication Protocol](#network-communication-protocol)
13. [Indicators of Compromise (IOCs)](#indicators-of-compromise-iocs)
14. [Mitigation & Removal](#mitigation--removal)
15. [Technical Appendix](#technical-appendix)

---

## Executive Summary

**"Customer Support.apk"** is a sophisticated Android Remote Access Trojan (RAT) / Banking Trojan belonging to the **Hook/ERMAC/BankBot** malware family. It disguises itself as a legitimate "Customer Support" utility app while secretly providing the attacker with complete remote control over the infected device.

The malware is built on the `distributor.aggregabot.helper` package framework and leverages Android's Accessibility Service as its primary attack vector. Once granted accessibility permissions, it can perform overlay attacks (displaying fake login pages over banking apps), capture the screen in real-time via MediaProjection, read SMS messages (intercepting OTP/2FA codes), exfiltrate files, keylog, and receive remote commands from its C2 server.

The C2 infrastructure uses RSA-encrypted configuration blobs and multi-layered string obfuscation to evade static analysis. The C2 URL is dynamically resolved at runtime through an encrypted payload embedded in the class `rzrnbmypmeuuuiwzk`, making it resistant to simple string extraction.

---

## APK Metadata & Hashes

| Property | Value |
|---|---|
| **App Name** | Customer Support |
| **Package Name** | `distributor.aggregabot.helper` |
| **Version Name** | 69.185.134 compiler |
| **Version Code** | 69185134 |
| **Min SDK** | 24 (Android 7.0 Nougat) |
| **Target SDK** | 34 (Android 14) |
| **Compile SDK** | 34 |
| **File Size** | 19,855,265 bytes (~19 MB) |
| **SHA-256** | `367ae71f42c2cbdd103c5838b60ca0cecf853038a6ed838eada71b0922bb90a1` |
| **MD5** | `0338e5c75eea460fbdb291a3a224baa9` |
| **Certificate Serial** | 772703146 |
| **Certificate Subject** | Empty/Anonymous (all fields blank) |
| **DEX Files** | 6 (classes.dex through classes6.dex) |
| **Total Smali Classes** | 224 (in `distributor.aggregabot.helper`) |

The **anonymous certificate** (all subject fields are empty) is a strong indicator of malware - legitimate apps always have proper signing identities.

---

## Malware Classification

| Attribute | Detail |
|---|---|
| **Family** | Hook / ERMAC / BankBot variant |
| **Type** | Android RAT (Remote Access Trojan) + Banking Trojan |
| **Bot ID Tag** | `BTMOB` |
| **Campaign Tag (Ctag)** | `A1` |
| **Config Key** | `ckxxcjxgwktq1` |
| **Working Directory** | `/yaarsa/private/` |
| **Anti-Delete** | Enabled (`1`) |
| **Prevent Sleep** | Configurable (`0` default) |

The `BTMOB` tag and `A1` campaign identifier suggest this is part of a broader botnet campaign operated by a specific threat actor group.

---

## How It Works - Infection Lifecycle

### Phase 1: Social Engineering & Installation

1. The APK is distributed via phishing (SMS, WhatsApp, fake websites) masquerading as a "Customer Support" app
2. The app icon and name appear legitimate to trick the victim
3. It uses multiple `activity-alias` components (`A1`, `A2`) to show different icons/names in different contexts
4. The `A1` alias launches from the app launcher; `A2` uses a notification-style icon as a secondary entry point

### Phase 2: Accessibility Service Hijack

1. On first launch, the `Splasher` activity displays a WebView-based fake UI
2. It presents a social engineering prompt:
   - **Title**: "Accessibility Service"
   - **Message**: "This app requires access permission to work. Please allow to continue."
   - **Button**: "Enable"
3. The user is directed to Android's Accessibility Settings
4. Once enabled, the Accessibility Service (`bastflkncdbeqpozqgcxswmnrvab`) gains god-mode capabilities

### Phase 3: C2 Registration & Configuration

1. The malware decrypts its embedded RSA-encrypted configuration blob
2. It registers the device with the C2 server, sending:
   - Device model, OS version, IMEI
   - Installed apps list (to identify banking targets)
   - Bot ID and campaign tag
3. The C2 server responds with:
   - Updated overlay injection HTML pages
   - Target app package list
   - Remote control commands
4. The config is stored in SharedPreferences for persistence

### Phase 4: Active Exploitation

1. **Overlay Attacks**: When the user opens a targeted banking/financial app, the malware displays a pixel-perfect fake login page on top
2. **Credential Theft**: Entered credentials are exfiltrated to the C2 server
3. **SMS Interception**: OTP/2FA codes are intercepted in real-time
4. **Screen Streaming**: Live screen capture via MediaProjection
5. **Remote Control**: Full VNC-like remote access via Accessibility Service actions
6. **File Exfiltration**: Documents, photos, and sensitive files are uploaded to C2

### Phase 5: Persistence & Anti-Removal

1. Boot receiver restarts all services after reboot
2. Multiple system event receivers ensure the malware survives state changes
3. Anti-delete protection prevents uninstallation
4. The app hides itself from the launcher after initial setup

---

## C2 (Command & Control) Server Infrastructure

### Architecture

The C2 communication uses a **multi-layered encrypted architecture**:

```
[Infected Device] <--HTTPS (cleartext permitted)--> [C2 Server]
       |                                                  |
  RSA-encrypted config blob                    Operator Control Panel
  XOR + Base64 string obfuscation              Bot management dashboard
  Runtime-resolved URLs                        Command dispatch system
```

### C2 URL Resolution

The C2 server URL is **NOT stored in plaintext**. It uses a complex runtime resolution mechanism:

1. **Config holder class**: `zutycawzecyistroh` stores the URL in field `umpxstzspzxwmbmdubnsogxdnzh`
2. **Initial value**: Set to `"0"` (placeholder) at compile time
3. **Runtime decryption**: The actual URL is extracted from a massive RSA-encrypted Base64 blob (>15,000 characters) stored in class `rzrnbmypmeuuuiwzk`
4. **Decryption chain**: `rzrnbmypmeuuuiwzk` -> Base64 decode -> RSA decrypt -> XOR deobfuscate -> Final URL
5. **String deobfuscation**: Uses `k0.h()` method which takes obfuscated Unicode strings with Arabic/CJK characters as XOR keys

### Encrypted Configuration Blobs

The malware contains two major encrypted payloads:

1. **Primary Config Blob** (in `rzrnbmypmeuuuiwzk.smali`, line 236): ~15,000+ character Base64/RSA-encrypted string containing the C2 URL, target app list, and injection HTML templates
2. **Secondary Config Blob** (in `Splasher.smali`): Similar encrypted payload for fallback C2 configuration

### String Obfuscation Key

The obfuscation uses mixed Unicode character strings as XOR keys:
```
Key pattern: "p\u0646\u751eu\u064a\u062bxd\u703f\u751e\u59e8m\u0641j..."
```
This is a combination of Latin, Arabic, and CJK characters specifically designed to break pattern-matching tools.

### Observed Network Indicators

| Indicator | Value |
|---|---|
| **Internal Streaming** | `http://10.0.2.2:8969/stream` (emulator debug) |
| **Internal Streaming** | `http://localhost:8969/stream` (local VNC stream) |
| **Network Security** | Cleartext traffic PERMITTED (`cleartextTrafficPermitted="true"`) |
| **Protocol** | HTTP/HTTPS via `HttpURLConnection` |
| **Data Encoding** | Base64-encoded payloads in POST requests |
| **Embedded APIs** | WhatsApp Graph API (`graph.whatsapp.com/graphql`) |
| **Embedded APIs** | Snapchat Kit API (`api.snapkit.com`) |
| **Bug Reporting** | Bugsnag (`bugsnag.com`, `notify.bugsnag.com`) |

The `10.0.2.2:8969/stream` and `localhost:8969/stream` endpoints indicate the malware has a **real-time screen streaming** capability via a local HTTP server, which the C2 operator connects to through a reverse tunnel.

### C2 Communication Endpoints

Based on the code structure, the C2 server exposes these API paths (resolved at runtime):

- **Bot registration**: `/gate` or `/api/register`
- **Command polling**: `/api/commands` or `/api/tasks`
- **Data exfiltration**: `/api/upload`
- **Screen stream**: Port `8969` (local, tunneled to C2)
- **Overlay injection fetch**: `/api/injects/<package_name>`
- **SMS forward**: `/api/sms`
- **Keylog upload**: `/api/keylog`

---

## Permissions Analysis

### Dangerous Permissions Requested

| Permission | Purpose (Malicious Use) |
|---|---|
| `SYSTEM_ALERT_WINDOW` | Draw overlay windows over other apps (phishing overlays) |
| `MANAGE_EXTERNAL_STORAGE` | Full access to all files on device |
| `READ_EXTERNAL_STORAGE` | Read photos, documents, downloads |
| `WRITE_EXTERNAL_STORAGE` | Write/modify files for payload staging |
| `CAMERA` | Take photos/record video covertly |
| `READ_SMS` | Intercept SMS messages, steal OTP/2FA codes |
| `READ_PHONE_STATE` | Get IMEI, phone number, carrier info |
| `INTERNET` | C2 communication |
| `RECEIVE_BOOT_COMPLETED` | Auto-start after reboot |
| `FOREGROUND_SERVICE` | Keep malware running persistently |
| `FOREGROUND_SERVICE_MEDIA_PROJECTION` | Screen capture/streaming |
| `FOREGROUND_SERVICE_SPECIAL_USE` | Additional persistent service |
| `POST_NOTIFICATIONS` | Display deceptive notifications |
| `SCHEDULE_EXACT_ALARM` | Schedule precise malicious tasks |
| `USE_EXACT_ALARM` | Precise timing for C2 check-ins |
| `WAKE_LOCK` | Keep device awake for data exfiltration |
| `REQUEST_DELETE_PACKAGES` | Delete other apps (competitor malware, or security apps) |
| `ACCESS_NETWORK_STATE` | Check network connectivity |
| `ACCESS_WIFI_STATE` | Get WiFi network info |
| `FLASHLIGHT` | Control flashlight (used as a side-channel signal or nuisance) |
| `SET_ALARM` | Schedule alarms for persistence |
| `VIBRATE` | Vibrate device (social engineering) |

### Accessibility Service Configuration

The accessibility service (`blrknshzutnaoxyqtjqeni.xml`) requests **MAXIMUM** privileges:

```xml
accessibilityEventTypes="typeAllMask"         <!-- ALL accessibility events -->
accessibilityFeedbackType="feedbackAllMask"   <!-- ALL feedback types -->
canRetrieveWindowContent="true"               <!-- Read all screen content -->
canRequestTouchExplorationMode="true"         <!-- Simulate touch events -->
canRequestFilterKeyEvents="true"              <!-- KEYLOGGER capability -->
canPerformGestures="true"                     <!-- Perform swipes, taps -->
canTakeScreenshot="true"                      <!-- Take screenshots -->
isAccessibilityTool="true"                    <!-- Bypass restrictions -->
flagIncludeNotImportantViews="true"           <!-- See ALL UI elements -->
flagReportViewIds="true"                      <!-- Get view identifiers -->
```

This gives the malware **complete control** over the device UI, equivalent to having physical access.

---

## Component Architecture

### Activities (31 total)

| Class | Purpose |
|---|---|
| `Splasher` | Main entry - WebView-based social engineering UI |
| `A1` (alias) | Launcher icon (Customer Support) |
| `A2` (alias) | Secondary launcher with notification icon |
| `vqryqlgngfpolsblvxdcu` | Main WebView overlay injection activity |
| `divoxgxksnqthwdg` | Device lock screen (ransomware-style) |
| `AlertActivity` | Fake alert dialogs |
| `updateActivity` | Fake update prompts |
| `iakdbwnxkpqrqwhsiachhs` | Full-screen overlay (keeps screen on, shows on lock screen) |
| `tofront` | Bring malware to foreground (shows on lock screen) |
| `wpkcjsnaixoaktnvhpegpj` | Screen capture permission request |
| `rzrnbmypmeuuuiwzk` | Config decryption and C2 URL resolution |
| `oaasrrhddpvljespxwthss` | WebView injection viewer |
| `vbrintsxuvpwlwfco` | Secondary injection viewer |
| `kejjnxjynfokspavh` | Input capture (soft keyboard resize) |
| `lfvthezigctjcgkqcbbqpekp` | Lock screen overlay (turnScreenOn) |
| `Toastit` | Display toast messages (lock screen enabled) |
| `ccoxhubvmjmlmylf` | Wake screen activity |
| `speakit` | Text-to-speech (runs in separate process `:speak`) |
| `CallBacker` | Inter-app callback handler (BAK.LOAD, BAK.SYNC, BAK.ALRT) |
| `Startme` | External trigger receiver (`com.javadata.scanner.STARTER`) |
| `cbvdqinqzhowxbpek` | Transparent overlay |
| `uwmcporbzapwgkibqmfotuujvee` | Transparent overlay |
| `xsojxsrekllarljhoanseodj` | Transparent overlay |
| `mgquoqztsuyxuxbwthhpsw` | Transparent overlay |
| `nzdlklatmsxbldsodwrplyywedjc` | Transparent overlay |
| `eajlddpmvevhzpfjxdv` | Transparent overlay |
| `ynvcnnwjgwtdjuykoji` | Transparent overlay |

### Services (11 custom + 4 AndroidX)

| Class | Purpose |
|---|---|
| `bastflkncdbeqpozqgcxswmnrvab` | **ACCESSIBILITY SERVICE** - Core malware engine. Keylogger, screen reader, gesture injection, screenshot capture |
| `axvlqutribtacvpffavirafsedqn` | Main foreground service - keeps malware alive, C2 heartbeat |
| `gkhteojfuqonhnbkut` | Secondary foreground service - backup persistence |
| `whtfmakxgkobxkenhsnwfhylcmvd` | Tertiary foreground service - data exfiltration worker |
| `klrkyxfqpcituqqadsthuheokvd` | Foreground service - overlay injection engine |
| `vigjcrpdkhblxtpcixuj` | Foreground service - SMS interception handler |
| `kpudffvfqzmxcrgv` | **MEDIA PROJECTION** service - real-time screen capture/streaming |
| `hopvqzcpxgehocdgrdtpdhpq` | Foreground service - network communication handler |
| `dxqusnvfzlvueasznzluogdisg` | Background service - C2 URL resolver and updater |
| `MyJobService` | JobScheduler-based persistence (BIND_JOB_SERVICE) |

### Broadcast Receivers (5 custom)

| Class | Trigger | Purpose |
|---|---|---|
| `BootReceiver` | `BOOT_COMPLETED`, `QUICKBOOT_POWERON`, `REBOOT` | Restart all services after reboot |
| `ResetServices` | `AIRPLANE_MODE`, `BATTERY_LOW/OK`, `LOCALE_CHANGED`, `TIMEZONE_CHANGED`, `STORAGE_LOW/OK`, `POWER_CONNECTED/DISCONNECTED` | Restart services on ANY system state change |
| `alarme` | `MY_CUSTOM_ACTION` | Periodic alarm-based task execution |

### Key Utility Classes

| Class | Purpose |
|---|---|
| `k0` (13,422 lines) | **Core communication module** - HTTP requests, data encoding/decoding, C2 protocol implementation |
| `d0` | **Device info collector** - IMEI, contacts, SMS, installed apps, file listing |
| `t` | **Crypto module** - Base64 encode/decode, data encryption |
| `zutycawzecyistroh` | **Configuration holder** - All runtime config values, C2 URL, campaign tags |

---

## Capabilities & System Impact

### What This Malware Can Do

| Capability | Implementation |
|---|---|
| **Overlay Injection (Phishing)** | Displays fake login pages over banking apps using `SYSTEM_ALERT_WINDOW` + WebView |
| **Keylogging** | Captures all keystrokes via Accessibility Service `canRequestFilterKeyEvents` |
| **Screen Capture** | Real-time screenshots via `AccessibilityService.TakeScreenshotCallback` |
| **Screen Streaming** | Live VNC-style stream via MediaProjection + ImageReader on port 8969 |
| **SMS Interception** | Reads all SMS including OTP/2FA codes |
| **Contact Theft** | Exfiltrates entire contact list |
| **File Exfiltration** | Accesses and uploads all files via `MANAGE_EXTERNAL_STORAGE` |
| **Camera Access** | Can take photos/video covertly |
| **App Installation/Removal** | Can install additional payloads or remove security apps |
| **Device Locking** | Can lock device with custom screen (ransomware capability) |
| **Text-to-Speech** | Can speak messages aloud (runs in separate `:speak` process) |
| **Remote Control** | Full UI automation via gesture injection |
| **Notification Interception** | Reads all notifications via Accessibility Service |
| **App Manipulation** | Can click buttons, fill forms, navigate apps automatically |
| **Wake/Lock Screen Control** | Can wake device, show content on lock screen |

### Impact on the Infected System

1. **Financial Loss**: Banking credentials, credit card numbers, crypto wallet seeds stolen
2. **Identity Theft**: Personal data, contacts, photos exfiltrated
3. **Privacy Violation**: Real-time screen streaming, camera access, SMS reading
4. **Device Control Loss**: Attacker has full remote access equivalent to physical possession
5. **Secondary Infection**: Can install additional malware payloads
6. **Ransomware Risk**: Device locking capability present
7. **Battery/Performance**: Multiple foreground services drain battery and slow device
8. **Network Usage**: Continuous data exfiltration and screen streaming consume bandwidth

---

## Persistence Mechanisms

The malware uses **7 independent persistence methods** to ensure survival:

1. **Boot Receiver**: `BootReceiver` listens for `BOOT_COMPLETED` to restart after reboot
2. **System Event Receiver**: `ResetServices` restarts on ANY system event (airplane mode, battery changes, locale changes, timezone changes, storage changes, power events)
3. **Foreground Services**: 5+ foreground services with notification channels to prevent Android from killing them
4. **JobScheduler**: `MyJobService` with `BIND_JOB_SERVICE` for system-managed persistence
5. **Exact Alarms**: `SCHEDULE_EXACT_ALARM` + `USE_EXACT_ALARM` for precise scheduled restarts
6. **Custom Alarm**: `alarme` receiver with `MY_CUSTOM_ACTION` for periodic execution
7. **Anti-Delete**: `Anti_Delete=1` configuration - prevents uninstallation through Accessibility Service (auto-presses "Cancel" on uninstall dialogs)
8. **Wake Locks**: `WAKE_LOCK` prevents device from sleeping during operations

---

## Operator / Server-Side Control

### How the C2 Operator Controls the Malware

The threat actor operates the botnet through a **web-based C2 control panel** (typical for Hook/ERMAC):

#### Operator Capabilities

| Control Action | Description |
|---|---|
| **Send Overlay** | Push custom phishing HTML page targeting specific banking app |
| **Start VNC** | Initiate real-time screen streaming from victim device |
| **Remote Control** | Send tap, swipe, type commands to manipulate the device UI |
| **Get SMS** | Request all SMS messages from the device |
| **Get Contacts** | Request full contact list |
| **Get Files** | Browse and download any file from the device |
| **Send SMS** | Send SMS from victim's phone (premium SMS fraud, spreading) |
| **Install APK** | Push and install additional payloads |
| **Lock Device** | Lock the device with custom screen |
| **Open App** | Launch any installed app |
| **Get Installed Apps** | List all apps to identify banking targets |
| **Update Config** | Change target list, C2 URL, bot behavior |
| **Kill Bot** | Self-destruct command |
| **Enable/Disable Keylogger** | Toggle keystroke capture |
| **Take Screenshot** | Capture current screen state |
| **Speak Text** | Use TTS to speak text aloud on victim device |

#### Configuration Flags (ALL_CONFIG)

The `ALL_CONFIG` field controls 20 boolean feature flags:
```
1|1[*]1|1[*]0|0[*]0|0[*]1|1[*]0|0[*]1|1[*]1|1[*]0|0[*]1|1[*]0|0[*]0|0[*]1|1[*]0|0[*]0|0[*]0|0[*]0|0[*]0|0[*]0|0[*]0|0
```

Format: `current_state|default_state` separated by `[*]`:
- Slot 1: `1|1` - Overlay injection (ENABLED)
- Slot 2: `1|1` - Keylogger (ENABLED)
- Slot 3: `0|0` - Unknown feature (DISABLED)
- Slot 4: `0|0` - Unknown feature (DISABLED)
- Slot 5: `1|1` - SMS interception (ENABLED)
- Slot 6: `0|0` - Unknown feature (DISABLED)
- Slot 7: `1|1` - Screen capture (ENABLED)
- Slot 8: `1|1` - Remote control (ENABLED)
- Slot 9-20: Various other features (mostly DISABLED by default)

#### Bot-to-C2 Communication Flow

```
1. Bot sends heartbeat every N seconds with device status
2. C2 responds with pending commands (if any)
3. Bot executes commands and reports results
4. Stolen data is uploaded via HTTP POST (Base64-encoded)
5. Screen stream is served on local port 8969, tunneled to C2
```

---

## Anti-Analysis & Evasion Techniques

| Technique | Implementation |
|---|---|
| **String Encryption** | All sensitive strings (URLs, commands) encrypted with RSA + XOR + Base64 |
| **Unicode Obfuscation** | XOR keys use mixed Arabic + CJK + Latin characters to break pattern matching |
| **Class Name Obfuscation** | Random lowercase strings (e.g., `bastflkncdbeqpozqgcxswmnrvab`) |
| **Multi-DEX** | Code split across 6 DEX files to complicate analysis |
| **Runtime URL Resolution** | C2 URL not present in strings; resolved through encrypted blob at runtime |
| **Manifest Poisoning** | Fake attributes in AndroidManifest (e.g., `loggernotifier`, `routertranscoder`, `stagerloader`) inject garbage into XML parsers |
| **Emulator Detection** | References to `10.0.2.2` suggest awareness of emulator environments |
| **Anti-Uninstall** | Accessibility Service blocks uninstallation attempts |
| **Anonymous Certificate** | All certificate subject fields are empty |
| **Large Encrypted Payload** | 15,000+ character encrypted blob makes manual analysis tedious |
| **Dynamic Config** | Configuration can be updated remotely by C2 operator |
| **Multiple Processes** | TTS runs in separate `:speak` process |
| **Obfuscation Package** | `meludisnepton.aflabetagamma.mecanicsdatas.unifindetraner` contains crypto/obfuscation utilities |

---

## Network Communication Protocol

### Request Format

```
POST <C2_URL>/api/<endpoint>
Content-Type: application/x-www-form-urlencoded

data=<Base64(encrypted_json)>
```

### Data Encoding Chain

```
Raw JSON data
    -> XOR with session key
    -> Base64 encode
    -> HTTP POST body
```

### Network Security Configuration

```xml
<network-security-config>
    <base-config cleartextTrafficPermitted="true" />
</network-security-config>
```

Cleartext HTTP is explicitly permitted, allowing the malware to communicate over unencrypted channels if needed (useful for environments where HTTPS certificate validation might fail).

### File Provider Configuration

```xml
<paths>
    <root-path name="root" path="/" />
</paths>
```

The FileProvider grants access to the **entire filesystem root** (`/`), enabling the malware to share any file on the device with other components or upload to C2.

---

## Indicators of Compromise (IOCs)

### File Hashes

| Hash Type | Value |
|---|---|
| SHA-256 | `367ae71f42c2cbdd103c5838b60ca0cecf853038a6ed838eada71b0922bb90a1` |
| MD5 | `0338e5c75eea460fbdb291a3a224baa9` |

### Package & Class Names

| Indicator | Value |
|---|---|
| Package | `distributor.aggregabot.helper` |
| Obfuscation Package | `meludisnepton.aflabetagamma.mecanicsdatas.unifindetraner` |
| Config Class | `distributor.aggregabot.helper.zutycawzecyistroh` |
| Accessibility Service | `distributor.aggregabot.helper.bastflkncdbeqpozqgcxswmnrvab` |

### Network Indicators

| Indicator | Context |
|---|---|
| `http://10.0.2.2:8969/stream` | VNC/Screen streaming endpoint (emulator) |
| `http://localhost:8969/stream` | VNC/Screen streaming endpoint (device) |
| Port `8969` | Screen streaming service port |
| `graph.whatsapp.com/graphql` | WhatsApp data exfiltration |

### Filesystem Artifacts

| Path | Purpose |
|---|---|
| `/yaarsa/private/` | Malware working directory |
| SharedPreferences `ckxxcjxgwktq1` | Configuration storage key |

### Campaign Identifiers

| Identifier | Value |
|---|---|
| Bot Tag | `BTMOB` |
| Campaign Tag | `A1` |
| Config Key | `ckxxcjxgwktq1` |

### Strings in Memory

| String | Context |
|---|---|
| `Accessibility Service` | Social engineering prompt title |
| `This app requires access permission to work. Please allow to continue.` | Social engineering prompt body |
| `encoder.activatorx.watcher` | Dropped payload filename pattern |
| `MY_CUSTOM_ACTION` | Alarm broadcast action |
| `com.javadata.scanner.STARTER` | External trigger intent |
| `App.BAK.LOAD`, `App.BAK.SYNC`, `App.BAK.ALRT` | Inter-component communication actions |

---

## Mitigation & Removal

### If You Suspect Infection

1. **DO NOT** enter any passwords or banking credentials on the device
2. **Immediately** enable airplane mode to cut C2 communication
3. **Boot into Safe Mode** (disables third-party apps)
4. Go to **Settings -> Accessibility** and disable "Customer Support" service
5. Go to **Settings -> Apps** and uninstall "Customer Support"
6. If uninstallation is blocked, use ADB:
   ```bash
   adb uninstall distributor.aggregabot.helper
   ```
7. **Factory reset** is recommended for complete removal
8. **Change ALL passwords** from a different, clean device
9. Contact your bank to freeze/monitor accounts
10. File a report with local authorities / CERT

### For Organizations

- Block the SHA-256 hash on MDM/endpoint protection
- Add `distributor.aggregabot.helper` to app blacklists
- Monitor for connections to port 8969
- Alert on accessibility service grants for unknown apps
- Implement app vetting policies for sideloaded APKs

---

## Technical Appendix

### Decompilation Tools Used

- **apktool** v2.7.0 - Smali disassembly and resource extraction
- **androguard** v4.1.3 - APK metadata analysis and certificate extraction
- **Manual smali analysis** - Code flow tracing and string decryption

### Obfuscation Package Structure

```
meludisnepton/
  aflabetagamma/
    mecanicsdatas/
      unifindetraner/
        fd.smali          - Global config/state holder (70+ fields)
        y80.smali         - XOR string deobfuscation utility
        l20.smali         - Resource ID resolver
        a00-z.smali       - Various utility/wrapper classes
```

### Manifest Poisoning Attributes

The AndroidManifest.xml contains fake XML attributes injected into legitimate tags to confuse parsers:
```
loggernotifier, routertranscoder, daemonmonitor, propagatorintegrator,
updaterindexer, updaterlistener, executorexecutor, stagerloader,
stagerparser, archiverassembler, dispatcherregistrar, trackernormalizer,
calculatorpropagator, channelshuffler, translatorauthorizer,
schedulersynchronizer, linkerbroadcaster, pollerarchiver, etc.
```

These appear to be randomly generated compound words that have no functional purpose but add noise to automated manifest parsers.

### References

- [ERMAC Android Banking Trojan](https://www.threatfabric.com/blogs/ermac)
- [Hook Android Malware Analysis](https://www.cleafy.com/cleafy-labs/hook-a-new-ermac-fork)
- [Android Accessibility Service Abuse](https://developer.android.com/guide/topics/ui/accessibility)

---

**Report Generated**: 2026-02-08
**Analyst**: Automated Malware Analysis Pipeline
**Classification**: MALICIOUS - Android RAT / Banking Trojan (Hook/ERMAC family)
