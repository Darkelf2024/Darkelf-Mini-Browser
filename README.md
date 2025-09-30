# Darkelf Mini Browser

**Stealth. Private. Hardened. Ephemeral.**  
A next-generation privacy mini browser based on PySide6 and QtWebEngine, featuring Tor integration, advanced anti-fingerprinting, and stealth network-level adblock.

![Darkelf Mini Browser](https://github.com/Darkelf2024/Darkelf-Mini-Browser/blob/main/Darkelf-Mini-Images/DE%20Mini%20Home.png)

---

## Features

- **Network-level Adblock**: Blocks requests to known ad/tracker domains for stealth privacy.
- **UA-CH & Client-Hints Stripping**: Removes all identifying headers and browser hints.
- **SuperHardenedPage**: Injects hundreds of anti-fingerprinting and anti-tracking shields before any page JS runs.
- **TOR Support**: Easy routing via Tor, with optional local Tor launcher and proxy fallback.
- **Letterboxing**: Window and screen dimensions spoofed for anti-fingerprinting (Tor Browser style).
- **No Persistent Cookies or Cache (Ephemeral)**: Session-only privacy; disables all persistent tracking vectors. *No cookies, cache, or site data survives across sessions.*
- **UI Features**: Tabbed browsing, custom homepage, history dialog, shortcuts, dark theme, and more.
- **Security Shields**:
  - *WebGL/WebRTC/Canvas/Audio API blocking*: **Canvas fingerprinting APIs are blocked at the source**—calls return blank or inaccessible, not just randomized.
  - *Supercookie and persistent storage kill*: Blocks localStorage, sessionStorage, IndexedDB, WebSQL, BroadcastChannel, SharedWorker, ServiceWorker, and more.
  - *Fingerprinting API blocks*: WebRTC, WebAuthn, Bluetooth, Battery, Permissions, Network Information, Device Memory, Idle Detector, FontFaceSet, Speech Synthesis, WebGPU.
  - *Navigator and screen spoofing*: User-agent, platform, plugins, hardwareConcurrency, deviceMemory, timezone, language, and more.
  - *Cookie banner killer*: Removes or auto-rejects cookie dialogs and banners.
  - *Strict Content Security Policy (CSP)*: Applies CSP meta at document creation, blocking mixed content and dangerous vectors.
  - *Referrer/header defense*: Removes referrer headers and applies `no-referrer` policy everywhere.
  - *Canvas/WebGL/Font randomization*: Adds noise/randomization for fingerprint-resistant rendering, except Canvas which is **blocked**.
  - *Audio fingerprint resistance*: Returns static or randomized responses to fingerprinting attempts.
  - *Font fingerprinting defense*: Spoofs font properties and disables precise measurements.
  - *WebSocket/eval/function monitoring*: Intercepts and logs suspicious evals, disables WebSocket.
  - *Tracking request blocker*: Prevents network requests to common tracker/analytics endpoints.
  - *Media devices spoofing*: Removes or disables access to camera/microphone APIs.
  - *Iframe hardening*: Poisons and optionally removes iframes to block cross-origin leaks.
  - *Idle/timing fuzzing*: Randomizes timing APIs for entropy reduction.

---

## Getting Started

### Prerequisites

- **Python 3.8+**
- **PySide6**
- **stem** (for Tor control)
- **Tor** (must be installed on your system)

### Installation

```sh
pip install PySide6 stem
# Install Tor on your system (macOS example):
brew install tor
```

### Running Darkelf Mini Browser

```sh
# Start with Tor (default)
python3.11 darkelf.py

# Or specify a custom proxy
python3.11 darkelf.py
```

---

## Usage

- **Tabs**: Ctrl+T (new tab), Ctrl+W (close tab)
- **Navigation**: Alt+Left/Right (back/forward), Ctrl+R (reload)
- **Zoom**: Ctrl+= / Ctrl+-
- **Full Screen**: F11
- **History**: Ctrl+H (view), menu for clearing
- **Search**: Enter query or URL in the search bar; defaults to DuckDuckGo Onion search for max privacy.

---

## Security & Privacy

- **No extensions**: All shields and adblock features are built-in, not loaded as browser extensions.
- **Script injection at document creation**: Shields run before page JS, blocking fingerprinting and tracking at the source.
- **Ephemeral privacy**: **No persistent storage**—no cookies, localStorage, sessionStorage, or IndexedDB survives across sessions.
- **TOR letterboxing**: Spoofs window/screen dimensions to defeat size-based fingerprinting.
- **Comprehensive fingerprinting resistance**: See above features for full coverage.
- **Hardened Chromium flags**: Disables background networking, WebRTC, HTTP2, WebGL, 3D APIs, breakpad, sync, plugins, third-party cookies, and more via `QTWEBENGINE_CHROMIUM_FLAGS`.

---

## Fingerprinting Test Results Explained

Darkelf Mini Browser is designed to defeat browser fingerprinting and tracking scripts. Here’s what you’ll observe with popular test sites:

### [Cover Your Tracks](https://coveryourtracks.eff.org/)
- **Result:** The test page will either show “test is running…” in a perpetual loop, or fail to complete.
- **Why:** Darkelf blocks key APIs (canvas, WebGL, audio, persistent storage, etc.), strips identifying headers, and randomizes screen/UA data. As a result, CoverYourTracks cannot collect enough information for a fingerprint and gets stuck in an endless test loop.

### [Am I Unique](https://amiunique.org/)
- **Result:** Most fields (especially entropy values) will display as `NaN` (Not a Number), or show generic/empty data.
- **Why:** With canvas, audio, and WebGL fingerprinting APIs disabled or randomized, and navigator/device properties spoofed, AmIUnique receives unparseable or “default” values, effectively breaking its fingerprinting calculations.

### [BrowserLeaks](https://browserleaks.com/)
- **Result:** Tests for Canvas, WebGL, Audio, Fonts, Media Devices, and Storage will be blank, spoofed, or display “undefined”/“blocked”/“null.”
- **Why:** These APIs are heavily shielded or disabled by Darkelf’s injected scripts before page JS runs. For example, **Canvas returns blank or blocked results** (not just noise), WebGL vendor/renderer are spoofed, and persistent storage is inaccessible.

#### What These Results Mean

- **“Stuck in a loop” or blank results:** The browser is successfully blocking fingerprinting vectors. Sites rely on these APIs/headers to build a unique profile; missing or spoofed data means you are not trackable by conventional browser fingerprinting.
- **NaN or generic values:** Indicates entropy has been removed and the site cannot distinguish your browser from others.
- **No persistent storage or cookies:** Your browsing cannot be correlated across sessions.
- **No unique identifiers:** No stable ID (like device IDs, canvas hashes, audio fingerprints, or plugin lists) is available for tracking.

**In short:**  
If fingerprinting/test sites cannot generate a unique browser profile or get stuck trying, Darkelf’s shields are working as intended. Your browser “looks like nothing” and cannot be uniquely identified or tracked.

---

## Contributing

Pull requests and issues welcome!  
See [issues](https://github.com/Darkelf2024/Darkelf-Browser/issues) for feature requests and bug reports.

---

## Acknowledgments

- Inspired by Tor Browser, KEM768, and the privacy community.
- [PySide6](https://wiki.qt.io/Qt_for_Python)
- [stem](https://stem.torproject.org/)
- [Tor](https://www.torproject.org/)

---

## Disclaimer

This browser is for research and educational purposes. While many privacy and security measures are implemented, no system is 100% secure. Always stay updated and use at your own risk.

---

## Security Features Reference

> This summary reflects the latest security features integrated in `Darkelf-Mini.ephemeral.py`:
- Chromium flags disabling tracking, fingerprinting, and networking vectors
- Tor-by-default, with proxy and DNS routing
- Composite interceptors for ad/tracker blocking and client-hint stripping
- SuperHardenedPage class with extensive JS shields, covering all known browser fingerprinting APIs
- Iframe hardening and mutation observer defense
- Letterboxing (window/screen dimension spoofing)
- No persistent cookies, cache, or storage (**ephemeral privacy**)
- Script injection at document creation for maximal coverage
- Cookie banner removal and auto-reject
- Font fingerprinting randomization and spoofing
- **Canvas fingerprinting API blocked (not just randomized)**
- WebGL noise injection and vendor spoofing
- Audio fingerprint resistance
- WebRTC, WebAuthn, Bluetooth, Battery, Permissions API hard blocks
- Strict CSP and referrer policy
- WebSocket and eval/function interception/logging
- History/cookie/cache auto-wipe
- Secure delete helpers (optional)
- All features auto-activate, no manual configuration required

For details, see the source code and [Privacy Policy](https://github.com/Darkelf2024/Darkelf-Browser/blob/main/Privacy%20Policy.md).
