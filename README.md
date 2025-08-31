# Darkelf Mini Browser

**Stealth. Private. Hardened.**  
A next-generation privacy mini browser based on PySide6 and QtWebEngine, featuring Tor integration, advanced anti-fingerprinting, and stealth network-level adblock.

---

## Features

- **Network-level Adblock**: Blocks requests to known ad/tracker domains for stealth privacy.
- **UA-CH & Client-Hints Stripping**: Removes all identifying headers and browser hints.
- **SuperHardenedPage**: Injects hundreds of anti-fingerprinting and anti-tracking shields before any page JS runs.
- **TOR Support**: Easy routing via Tor, with optional local Tor launcher and proxy fallback.
- **Letterboxing**: Window and screen dimensions spoofed for anti-fingerprinting (Tor Browser style).
- **No Persistent Cookies or Cache**: Session-only privacy; disables persistent tracking vectors.
- **UI Features**: Tabbed browsing, custom homepage, history dialog, shortcuts, dark theme, and more.
- **Security Shields**:
  - Blocks WebGL/WebRTC/Canvas/Audio APIs.
  - Disables supercookies, localStorage, sessionStorage, IndexedDB, and more.
  - Blocks fingerprinting APIs: WebRTC, WebAuthn, Bluetooth, Battery, Permissions, etc.
  - Kills cookie banners and trackers.
  - Applies strict Content Security Policy (CSP).

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
python darkelf.py

# Or specify a custom proxy
DARKELF_PROXY="socks5://127.0.0.1:9052" python darkelf.py
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
- **No persistent storage**: No cookies, localStorage, sessionStorage, or IndexedDB survives across sessions.
- **TOR letterboxing**: Spoofs window/screen dimensions to defeat size-based fingerprinting.

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
