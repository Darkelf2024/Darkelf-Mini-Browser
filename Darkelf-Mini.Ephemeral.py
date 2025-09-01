# Darkelf-Mini v3.0 — Ephemeral, Privacy-Focused Web Browser
# Copyright (C) 2025 Dr. Kevin Moore
#
# SPDX-License-Identifier: LGPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Lesser General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License along
# with this program. If not, see <https://www.gnu.org/licenses/>.
#
# PROJECT SCOPE (EPHEMERAL BUILD)
# Darkelf-Mini is designed to avoid writing user data to disk. In this build,
# settings, cookies, cache, history, and other WebEngine storage are kept in
# memory only and discarded on exit. Download requests are blocked by default.
# This minimizes local persistence; for defense-in-depth, use OS full-disk or
# swap encryption as appropriate for your environment.
#
# EXPORT / CRYPTOGRAPHY NOTICE
# This source distribution does not itself implement proprietary cryptographic
# algorithms. Any network encryption (e.g., TLS) is provided by third-party
# components (such as QtWebEngine and the operating system) under their
# respective licenses. If you build or distribute binaries that bundle such
# components, or if you add cryptographic code, you are responsible for
# complying with applicable export control laws (including the U.S. EAR) and
# any relevant license exceptions (e.g., TSU under 15 CFR §740.13(e)), as well
# as local regulations in jurisdictions of distribution and use.
#
# COMPLIANCE & RESTRICTIONS
# This software may not be exported, re-exported, or transferred, directly or
# indirectly, in violation of U.S. or other applicable sanctions and export
# control laws. Do not use this software in connection with the development,
# production, or deployment of weapons of mass destruction as defined by the
# EAR. By downloading, using, or distributing this software, you agree to comply
# with all applicable laws and regulations.
#
# NOTE
# This code is provided as source only. No compiled binaries are included in
# this distribution. Redistribution, modification, and use must comply with the
# LGPL-3.0-or-later and applicable export/usage restrictions.
#
# Authored by Dr. Kevin Moore, 2025.

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Darkelf Mini — PySide6
• Robust UA-CH stripping (no sec-ch-ua* leaks) via QWebEngineUrlRequestInterceptor
• SuperHardenedPage with your full shield pack (runs at DocumentCreation)
• Consolidated QTWEBENGINE_CHROMIUM_FLAGS (no duplicates)
• Tor support:
   - Env-based Chromium proxy (DARKELF_TOR=1 or DARKELF_PROXY=... at launch)
   - Optional local Tor launcher using stem (your init_tor/start_tor/etc added)
   - QNetworkProxy fallback wiring (note: Chromium’s net stack primarily honors --proxy-server)
• Tabbed UI, toolbar, shortcuts, custom homepage, history dialog
• Safe adblock stub (AdblockInterceptor)

Start with Tor proxy routing from launch:
  DARKELF_TOR=1 python darkelf.py
  # or custom:
  DARKELF_PROXY="socks5://127.0.0.1:9052" python darkelf.py
"""

import os
import sys
import shutil
import socket
import subprocess
import tempfile
import time
import secrets
import ssl
from pathlib import Path

from PySide6.QtWebChannel import QWebChannel
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QPushButton, QLineEdit, QVBoxLayout, QMenuBar, QToolBar, QDialog, QMessageBox, QFileDialog, QProgressDialog, QListWidget, QMenu, QWidget, QLabel, QToolButton, QSizePolicy, QFrame, QHBoxLayout, QTextEdit, QGraphicsDropShadowEffect, QWidget
)
from PySide6.QtGui import QPalette, QColor, QKeySequence, QShortcut, QAction, QGuiApplication, QActionGroup, QIcon, QPixmap, QPainter, QFont
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtNetwork import QNetworkProxy, QSslConfiguration, QSslSocket, QSsl, QSslCipher
from PySide6.QtWebEngineCore import (
    QWebEngineUrlRequestInterceptor, QWebEngineSettings, QWebEnginePage, QWebEngineScript, QWebEngineProfile,
    QWebEngineDownloadRequest, QWebEngineContextMenuRequest, QWebEngineCookieStore
)
from PySide6.QtCore import QUrl, QSettings, Qt, QObject, Slot, QTimer, QCoreApplication, Signal, QThread, QSize, QPoint, QByteArray

# Tor + Stem
import stem.process
from stem.connection import authenticate_cookie
from stem.control import Controller
from stem import Signal as StemSignal
from stem import process as stem_process

devnull = open(os.devnull, 'w')
os.dup2(devnull.fileno(), sys.stderr.fileno())

class EphemeralSettings:
    """Drop-in for QSettings that never touches disk."""
    def __init__(self, *args, **kwargs):
        self._mem = {}
    def setValue(self, key, value):
        self._mem[key] = value
    def value(self, key, default=None, type=None):
        v = self._mem.get(key, default)
        if type is bool:
            if isinstance(v, str):
                low = v.strip().lower()
                if low in ("1","true","yes","on"): return True
                if low in ("0","false","no","off",""): return False
            return bool(v)
        if type in (int, float, str) and v is not None:
            try:
                return type(v)
            except Exception:
                return v
        return v
    def remove(self, key): self._mem.pop(key, None)
    def contains(self, key): return key in self._mem
    def sync(self): pass
    def clear(self): self._mem.clear()

def make_off_the_record_profile(profile: QWebEngineProfile) -> QWebEngineProfile:
    """Configure WebEngine to keep everything in RAM and avoid persistence."""
    try:
        profile.setOffTheRecord(True)
    except Exception:
        pass
    try:
        profile.setPersistentCookiesPolicy(QWebEngineProfile.NoPersistentCookies)
        profile.setHttpCacheType(QWebEngineProfile.MemoryHttpCache)
    except Exception:
        pass
    try:
        profile.setCachePath("")
        profile.setPersistentStoragePath("")
        profile.setDownloadPath("")
    except Exception:
        pass
    return profile

THEME = {
    "accent": "#34C759",
    "accentDim": "#1aa050",
    "surface": "#0f1117",
    "bg": "#0a0b10",
    "stroke": "rgba(255,255,255,.12)",
    "text": "#e5e7eb",
}

DUCK_LITE_HTTPS = "https://duckduckgo.com/lite/?q="
DUCK_LITE_ONION = "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/lite/?q="
USE_ONION_SEARCH = True  # flip if you want onion search by default

MUTE_LOGS_AFTER_BOOT_MS = 0

# We run Tor by default and point Chromium at the SOCKS port our stem launcher uses.
DEFAULT_TOR = True
DEFAULT_TOR_SOCKS = "socks5://127.0.0.1:9052"   # matches start_tor() config

# Optional CLI/env still supported, but default is ON.
_cli_tor   = any(a in sys.argv for a in ("--tor", "--use-tor", "-T"))
_cli_proxy = next((a.split("=", 1)[1] for a in sys.argv if a.startswith("--proxy=")), "")

_env_tor = DEFAULT_TOR or _cli_tor or (os.environ.get("DARKELF_TOR", "").strip().lower() in ("1","true","yes","on"))
_env_proxy = (
    _cli_proxy
    or os.environ.get("DARKELF_PROXY", "").strip()
    or (DEFAULT_TOR_SOCKS if _env_tor else "")
)

# Build Chromium flags (add your existing ones below).
flags = []
if _env_proxy:
    flags.append(f'--proxy-server="{_env_proxy}"')

# If Tor is on by default, use onion search on the homepage automatically.
USE_ONION_SEARCH = bool(_env_tor)

# ... then append the rest of your existing hardening flags to `flags` ...
# flags += [ "--disable-features=...", "--disable-gpu", ... ]
os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = " ".join(flags + [
    # keep all the hardening flags you already had here (unchanged)
])
# --- end TOR DEFAULTS ---

_disable_features = [
    "AcceptCHFrame", "ClientHints", "UserAgentClientHints", "UserAgentReduction",
    "GreaseUACH", "ClientHintsDPR", "ClientHintsPixelRounding",
    "Canvas2DImageChromium", "WebGLImageChromium",
    "AudioServiceSandbox", "InterestCohortAPI", "PrivacySandboxAdsAPIs",
    "HTMLImports", "AudioContext", "HardwareConcurrency", "IndexedDB",
    "NetworkService", "PrefetchPrivacyChanges",
]
_disable_blink_features = ["ClientHints", "UserAgentClientHints", "UserAgentClient", "NavigatorOnLine"]
_enable_features = ["StrictOriginIsolation", "PartitionedCookies"]

flags = [
    f"--disable-features={','.join(sorted(set(_disable_features)))}",
    f"--disable-blink-features={','.join(sorted(set(_disable_blink_features)))}",
    f"--enable-features={','.join(sorted(set(_enable_features)))}",
    "--force-device-scale-factor=1",
    "--disable-webrtc", "--disable-http2", "--disable-webgl", "--disable-3d-apis",
    "--disable-rtc-sctp-data-channels", "--disable-rtc-multiple-routes", "--disable-rtc-stun-origin",
    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp", "--disable-rtc-event-log", "--disable-rtc-sdp-logs",
    "--disable-webgl-2", "--disable-gpu", "--disable-d3d11", "--disable-accelerated-2d-canvas",
    "--disable-software-rasterizer", "--disable-reading-from-canvas", "--disable-offscreen-canvas",
    "--use-angle=none", "--disable-extensions", "--disable-sync", "--disable-translate", "--disable-plugins",
    "--disable-client-side-phishing-detection", "--disable-font-subpixel-positioning", "--disable-kerning",
    "--disable-web-fonts", "--disable-background-networking", "--disable-speech-api", "--disable-sensor",
    "--disable-javascript-harmony", "--no-referrers", "--disable-renderer-backgrounding",
    "--disable-background-timer-throttling", "--disable-quic", "--disable-third-party-cookies",
    "--disable-webrtc-hw-encoding", "--disable-webrtc-hw-decoding", "--disable-webrtc-cpu-overuse-detection",
    "--disable-backgrounding-occluded-windows", "--disable-lcd-text", "--disable-accelerated-video",
    "--disable-gpu-compositing", "--disable-text-autosizing", "--disable-peer-connection",
    "--disable-breakpad", "--force-major-version-to-minor", "--disable-http-cache",
    "--cipher-suite-blacklist=0x0004,0x0005,0x002f,0x0035", "--disk-cache-dir=/dev/null",
    "--incognito", "--disable-gpu-shader-disk-cache", "--disk-cache-size=1",
    "--media-cache-size=1", "--disable-logging", "--no-pings", "--disable-background-networking",
    "--disable-component-update", "--disable-breakpad",
]

if _env_proxy:
    flags.append(f'--proxy-server="{_env_proxy}"')
os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = " ".join(flags)

class AdblockInterceptor(QWebEngineUrlRequestInterceptor):
    """Blocks requests to known ad domains for stealth adblocking."""
    def __init__(self, parent=None, ad_domains=None):
        super().__init__(parent)
        # Default ad/tracker domains. Add more as needed!
        self.ad_domains = set(ad_domains or [
            "doubleclick.net", "googlesyndication.com", "adsafeprotected.com", "adservice.google.com",
            "adnxs.com", "yieldmanager.com", "scorecardresearch.com", "quantserve.com",
            "securepubads.g.doubleclick.net", "pagead2.googlesyndication.com",
            "partner.googleadservices.com"
            # Add more domains for better coverage!
        ])
    def interceptRequest(self, info):  # type: ignore[override]
        try:
            url = info.requestUrl().toString().lower()
            if any(domain in url for domain in self.ad_domains):
                info.block(True)
            else:
                info.block(False)
        except Exception:
            # Never error: if unsure, allow the request
            info.block(False)

class StripClientHints(QWebEngineUrlRequestInterceptor):
    def interceptRequest(self, info):
        url = info.requestUrl().toString()
        # Always strip UA-CH headers (these are privacy/fingerprinting, not critical for networking)
        for h in (
            b"sec-ch-ua", b"sec-ch-ua-mobile", b"sec-ch-ua-platform",
            b"sec-ch-ua-full-version", b"sec-ch-ua-full-version-list",
            b"sec-ch-ua-arch", b"sec-ch-ua-bitness", b"sec-ch-ua-model",
            b"sec-ch-ua-form-factor", b"sec-ch-ua-wow64", b"sec-ch-ua-platform-version",
            b"x-client-data"
        ):
            info.setHttpHeader(h, b"")
        # Optionally: Only strip proxy headers for external sites (not .onion, not localhost)
        if not (".onion" in url or "127.0.0.1" in url or "localhost" in url):
            proxy_headers = [
                b"Via", b"X-Forwarded-For", b"Forwarded", b"HTTP_X_FORWARDED_FOR",
                b"HTTP_CLIENT_IP", b"HTTP_FORWARDED", b"HTTP_VIA"
            ]
            # DO NOT STRIP 'Proxy-Connection' - Chromium may require it
            for h in proxy_headers:
                info.setHttpHeader(h, b"")
        # Keep user-agent and proxy-connection intact for Chromium
        info.setHttpHeader(b"accept-language", b"en-US,en;q=0.9")
        info.setHttpHeader(b"referrer-policy", b"no-referrer")
        # Set DNT header for privacy
        try:
            info.setHttpHeader(QByteArray(b"DNT"), QByteArray(b"1"))
        except Exception:
            pass
            
class CompositeInterceptor(QWebEngineUrlRequestInterceptor):
    """One interceptor per profile → fan out to many. Accepts list OR varargs."""
    def __init__(self, *children, parent=None):
        super().__init__(parent)
        if len(children) == 1 and isinstance(children[0], (list, tuple)):
            children = tuple(children[0])
        self._children = [c for c in children if c is not None]
    def interceptRequest(self, info):  # type: ignore[override]
        for c in self._children:
            c.interceptRequest(info)
            
# --- UA-CH + Navigator hard lock (mixin) ---
class _UAChNavigatorHardMixin:
    def inject_uach_off_everywhere(self):
        script = r"""
        (() => {
        // remove on proto
        try { Object.defineProperty(Navigator.prototype, "userAgentData",
                { get: () => undefined, configurable: false }); } catch(_){}
        // remove on instance too
        try { Object.defineProperty(navigator, "userAgentData",
                { get: () => undefined, configurable: false }); } catch(_){}

        // strip UA-CH from fetch/XHR anyway
        const UA = "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0";
        const K = ["sec-ch-ua","sec-ch-ua-mobile","sec-ch-ua-platform","sec-ch-ua-platform-version",
                    "sec-ch-ua-arch","sec-ch-ua-bitness","sec-ch-ua-full-version","sec-ch-ua-full-version-list",
                    "accept-ch"];
        try {
            const ofetch = window.fetch;
            window.fetch = function(r, init = {}) {
            init.headers = new Headers(init.headers || {});
            K.forEach(k => { try { init.headers.delete(k); } catch(_){} });
            try { init.headers.set("user-agent", UA); } catch(_){}
            init.referrer = ""; init.referrerPolicy = "no-referrer";
            return ofetch(r, init);
            };
            const oopen = XMLHttpRequest.prototype.open;
            XMLHttpRequest.prototype.open = function(...a) {
            this.addEventListener("readystatechange", function() {
                if (this.readyState === 1) {
                try {
                    K.forEach(k => this.setRequestHeader(k, ""));
                    this.setRequestHeader("user-agent", UA);
                    this.setRequestHeader("Referer", "");
                    this.setRequestHeader("Referrer-Policy", "no-referrer");
                } catch(_){}
                }
            });
            return oopen.apply(this, a);
            };
        } catch(_){}
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation, subframes=True)

class _DarkelfLetterboxMixin:
    def inject_darkelf_letterboxing(self):
        script = r"""
        (() => {
          const W = 1000, H = 1000, OUT_W = W + 16, OUT_H = H + 88;
          const ro = (o, k, v) => { try { Object.defineProperty(o, k, { get: () => v, configurable: true }); } catch(_){} };

          ro(window, "innerWidth",  W);
          ro(window, "innerHeight", H);
          ro(window, "outerWidth",  OUT_W);
          ro(window, "outerHeight", OUT_H);
          ro(window, "devicePixelRatio", 1);

          ro(screen, "width", W); ro(screen, "height", H);
          ro(screen, "availWidth", W); ro(screen, "availHeight", H - 20);
          ro(screen, "availTop", 0); ro(screen, "availLeft", 0);
          ro(screen, "colorDepth", 24);
          ro(window, "screenX", 0); ro(window, "screenY", 0);

          if (window.visualViewport) {
            try {
              ro(window.visualViewport, "width",  W);
              ro(window.visualViewport, "height", H);
              ro(window.visualViewport, "scale",  1);
              ro(window.visualViewport, "offsetTop", 0);
              ro(window.visualViewport, "offsetLeft", 0);
            } catch(_){}
          }

          const origMM = window.matchMedia;
          window.matchMedia = function(q) {
            try {
              const m = String(q).toLowerCase();
              const yes = (
                /\(min\-width:\s*(\d+)px\)/.test(m) ? W >= +RegExp.$1 :
                /\(max\-width:\s*(\d+)px\)/.test(m) ? W <= +RegExp.$1 :
                /\(min\-height:\s*(\d+)px\)/.test(m) ? H >= +RegExp.$1 :
                /\(max\-height:\s*(\d+)px\)/.test(m) ? H <= +RegExp.$1 :
                false
              );
              return { matches: yes, media: q, onchange: null,
                       addListener: ()=>{}, removeListener: ()=>{},
                       addEventListener: ()=>{}, removeEventListener: ()=>{},
                       dispatchEvent: ()=>false };
            } catch(_) { return origMM.apply(this, arguments); }
          };

          window.addEventListener("resize", ev => {
            try { ev.stopImmediatePropagation?.(); ev.preventDefault?.(); } catch(_){}
          }, true);
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation, subframes=True)
        
class DarkelfHardenedProfile:
    """
    Helper to install JS and interceptor to fully block sec-ch-ua leaks
    and neutralize iframes, matching KEM768-level privacy.
    """
    @staticmethod
    def install(profile, remove_iframes=False):
        hardening_js = """
        (() => {
            // === 1. Remove sec-ch-ua and userAgentData everywhere ===
            Object.defineProperty(navigator, "userAgentData", { get: () => undefined, configurable: true });
            if (navigator.userAgentData && navigator.userAgentData.getHighEntropyValues)
                navigator.userAgentData.getHighEntropyValues = async function() { return {}; };

            // Remove sec-ch-ua headers from fetch/XHR
            const removeUAHeaders = headers => {
                if (headers && typeof headers.set === "function") {
                    [
                        "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "sec-ch-ua-full-version",
                        "sec-ch-ua-full-version-list", "sec-ch-ua-arch", "sec-ch-ua-bitness", "sec-ch-ua-model",
                        "sec-ch-ua-form-factor", "sec-ch-ua-wow64", "sec-ch-ua-platform-version", "user-agent", "x-client-data"
                    ].forEach(h => { try { headers.set(h, ""); } catch(_) {} });
                }
            };
            if (window.fetch) {
                const origFetch = window.fetch;
                window.fetch = function(resource, init = {}) {
                    init.headers = new Headers(init.headers || {});
                    removeUAHeaders(init.headers);
                    return origFetch(resource, init);
                };
            }
            if (window.XMLHttpRequest) {
                const origOpen = XMLHttpRequest.prototype.open;
                XMLHttpRequest.prototype.open = function(...args) {
                    this.addEventListener("readystatechange", function() {
                        if (this.readyState === 1) {
                            [
                                "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "sec-ch-ua-full-version",
                                "sec-ch-ua-full-version-list", "sec-ch-ua-arch", "sec-ch-ua-bitness", "sec-ch-ua-model",
                                "sec-ch-ua-form-factor", "sec-ch-ua-wow64", "sec-ch-ua-platform-version", "user-agent", "x-client-data"
                            ].forEach(h=>{
                                try { this.setRequestHeader(h, ""); } catch(_) {}
                            });
                        }
                    });
                    return origOpen.apply(this, args);
                };
            }

            // === 2. Poison all existing and future iframes ===
            function poisonIframe(frame) {
                try {
                    const w = frame.contentWindow;
                    if (w && w.navigator) {
                        Object.defineProperty(w.navigator, "userAgentData", { get: () => undefined, configurable: true });
                        Object.defineProperty(w.navigator, "platform", { get: () => "Win32", configurable: true });
                        Object.defineProperty(w.navigator, "userAgent", { get: () => "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101 Firefox/78.0", configurable: true });
                        Object.defineProperty(w.navigator, "vendor", { get: () => "", configurable: true });
                    }
                } catch(e) {}
            }
            Array.from(document.querySelectorAll("iframe")).forEach(poisonIframe);
            new MutationObserver(function(mutations){
                mutations.forEach(function(m){
                    Array.from(m.addedNodes).forEach(function(node){
                        if(node.tagName === "IFRAME"){
                            poisonIframe(node);
                            %REMOVE_IFRAMES%
                        }
                    });
                });
            }).observe(document, {childList: true, subtree: true});

            // === 3. Optionally Block/Remove all iframes ===
            %REMOVE_IFRAMES_TOP%
        })();
        """
        if remove_iframes:
            hardening_js = hardening_js.replace(
                "%REMOVE_IFRAMES%",
                "try { node.remove(); } catch(_) {}"
            ).replace(
                "%REMOVE_IFRAMES_TOP%",
                "document.querySelectorAll('iframe').forEach(frame => { try { frame.remove(); } catch(_) {} });"
            )
        else:
            hardening_js = hardening_js.replace("%REMOVE_IFRAMES%", "").replace("%REMOVE_IFRAMES_TOP%", "")

        script = QWebEngineScript()
        script.setName("darkelf-hardened-iframe-leakblock")
        script.setSourceCode(hardening_js)
        script.setInjectionPoint(QWebEngineScript.DocumentCreation)
        script.setWorldId(QWebEngineScript.MainWorld)
        script.setRunsOnSubFrames(True)
        profile.scripts().insert(script)

        # Set the client hints interceptor
        profile.setUrlRequestInterceptor(StripClientHints())
        
# class header
class SuperHardenedPage(QWebEnginePage, _UAChNavigatorHardMixin, _DarkelfLetterboxMixin):
    def __init__(self, profile, parent=None):
        super().__init__(profile, parent)
        self.profile = profile
        self.inject_all_scripts()
        self.featurePermissionRequested.connect(self.onFeatureRequested)

    def onFeatureRequested(self, origin, feature):
        self.setFeaturePermission(origin, feature, QWebEnginePage.PermissionPolicy.DeniedByUser)

    def inject_script(self, script_str, injection_point=QWebEngineScript.DocumentReady, subframes=True):
        script = QWebEngineScript()
        script.setSourceCode(script_str)
        script.setInjectionPoint(injection_point)
        script.setWorldId(QWebEngineScript.MainWorld)
        script.setRunsOnSubFrames(subframes)
        self.profile.scripts().insert(script)
        
    def setup_ssl_configuration(self):
        configuration = QSslConfiguration.defaultConfiguration()
        configuration.setProtocol(QSsl.TlsV1_3)
        QSslConfiguration.setDefaultConfiguration(configuration)
        
    # ---- All your shield methods, trimmed for brevity-critical bits ----
    def inject_all_scripts(self):
        self.inject_uach_off_everywhere()
        self.inject_darkelf_letterboxing()
        self.inject_canvas_protection()
        self.inject_geolocation_override()
        self.inject_useragentdata_kill()
        self.inject_navigator_prototype_spoof()
        self.enable_user_select_script()
        self.enable_scrolling_script()
        self.inject_stealth_profile()
        self.block_shadow_dom_inspection()
        self.block_tracking_requests()
        self.protect_fingerprinting()
        self.spoof_canvas_api()
        self.stealth_webrtc_block()
        self.block_webrtc_sdp_logging()
        self.block_supercookies()
        self.block_etag_and_cache_tracking()
        self.block_referrer_headers()
        self.spoof_plugins_and_mimetypes()
        self.spoof_timezone()
        self.spoof_media_queries()
        self.spoof_battery_api()
        self.spoof_network_connection()
        self.spoof_device_memory()
        self.disable_pointer_detection()
        self.block_cookie_beacon_getstats()
        self.block_audio_context()
        self.spoof_navigator_basics()
        self.block_window_chrome()
        self.spoof_permissions_api()
        self.fuzz_timing_functions()
        self.spoof_storage_estimate()
        self.block_fontfaceset_api()
        self.block_idle_detector()
        self.spoof_language_headers()
        self.hide_webdriver_flag()
        self.block_webauthn()
        self.patch_youtube_compatibility()
        self.block_fedcm_api()
        self.block_speech_synthesis()
        self.clamp_performance_timers()
        self.spoof_audio_fingerprint_response()
        self.block_web_bluetooth()
        self.block_cookie_banners()
        self.block_webgpu_api()
        self.harden_webworkers()
        self._inject_font_protection()
        self.spoof_font_loading_checks()
        self.inject_useragentdata_kill()
        self.inject_webgl_spoof()
        self.inject_iframe_override()
        self.setup_csp()

    def inject_geolocation_override(self):
        script = """
        (function() {
            // Completely remove navigator.geolocation
            Object.defineProperty(navigator, "geolocation", {
                get: function () {
                    return undefined;
                },
                configurable: true
            });

            // Fake permissions API to return denied
            if (navigator.permissions && navigator.permissions.query) {
                const originalQuery = navigator.permissions.query;
                navigator.permissions.query = function(parameters) {
                    if (parameters.name === "geolocation") {
                        return Promise.resolve({ state: "denied" });
                    }
                    return originalQuery(parameters);
                };
            }
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)

    def inject_iframe_override(self):
        script = """
        (function() {
            const poisonIframe = (frame) => {
                try {
                    if (frame.contentWindow && frame.contentWindow.navigator) {
                        frame.contentWindow.navigator.geolocation = undefined;
                        Object.defineProperty(frame.contentWindow.navigator, 'platform', { value: 'unknown', configurable: true });
                        Object.defineProperty(frame.contentWindow.navigator, 'vendor', { value: '', configurable: true });
                    }
                } catch (e) {
                    // Ignore cross-origin issues
                }
            };

            // Poison existing iframes
            document.querySelectorAll('iframe').forEach(poisonIframe);

            // Observe for dynamically added iframes
            const observer = new MutationObserver(function(mutations) {
                for (let mutation of mutations) {
                    for (let node of mutation.addedNodes) {
                        if (node.tagName === 'IFRAME') {
                            poisonIframe(node);
                        }
                    }
                }
            });

            observer.observe(document, { childList: true, subtree: true });
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)
        
    def enable_user_select_script(self):
        script = """
        (() => {
          // Ensure all text is selectable
          document.body.style.userSelect = "text";
          document.documentElement.style.userSelect = "text";
          // Remove any CSS classes that block selection
          document.body.classList.remove('noselect','no-select','user-select-none');
          document.documentElement.classList.remove('noselect','no-select','user-select-none');
          // Remove inline user-select:none
          Array.from(document.querySelectorAll('*')).forEach(el => {
            if (getComputedStyle(el).userSelect === 'none')
              el.style.userSelect = 'text';
          });
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentReady, subframes=True)
        
    def enable_scrolling_script(self):
        script = """
        (() => {
          // Remove overflow: hidden from html/body if present
          document.documentElement.style.overflow = "auto";
          document.body.style.overflow = "auto";
          // Remove CSS classes that might block scrolling
          document.documentElement.classList.remove('overflow-hidden');
          document.body.classList.remove('overflow-hidden');
          // Ensure scrolling is enabled
          document.documentElement.style['-webkit-overflow-scrolling'] = "touch";
          document.body.style['-webkit-overflow-scrolling'] = "touch";
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentReady, subframes=True)
        
    def inject_webgl_spoof(self):
        script = """
        (function () {
            const spoofedVendor = "Intel Inc.";
            const spoofedRenderer = "Intel Iris Xe Graphics";

            function spoofGL(context) {
                const originalGetParameter = context.getParameter;
                context.getParameter = function (param) {
                    if (param === 37445) return spoofedVendor;   // UNMASKED_VENDOR_WEBGL
                    if (param === 37446) return spoofedRenderer; // UNMASKED_RENDERER_WEBGL
                    return originalGetParameter.call(this, param);
                };
            }

            const originalGetContext = HTMLCanvasElement.prototype.getContext;
            HTMLCanvasElement.prototype.getContext = function(type, attrs) {
                const ctx = originalGetContext.call(this, type, attrs);
                if (type === "webgl" || type === "webgl2") {
                    spoofGL(ctx);
                }
                return ctx;
            };

            // Spoof WebGLRenderingConapply extensions
            WebGLRenderingContext.prototype.getSupportedExtensions = function () {
                return [
                    "OES_texture_float", 
                    "OES_standard_derivatives", 
                    "OES_element_index_uint"
                ];
            };

            // Spoof shader precision to reduce entropy
            const origPrecision = WebGLRenderingContext.prototype.getShaderPrecisionFormat;
            WebGLRenderingContext.prototype.getShaderPrecisionFormat = function() {
                return { rangeMin: 127, rangeMax: 127, precision: 23 };
            };

            // Prevent detection of overridden functions
            const hideOverride = (obj, name) => {
                if (obj[name]) {
                    Object.defineProperty(obj[name], 'toString', {
                        value: () => `function ${name}() { [native code] }`
                    });
                }
            };

            hideOverride(WebGLRenderingContext.prototype, "getParameter");
            hideOverride(HTMLCanvasElement.prototype, "getContext");
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)
        
    def inject_canvas_protection(self):
        script = """
        (() => {
            // Helper: clone and add noise to ImageData
            function noisyImageData(imgData) {
                const copy = new ImageData(
                    new Uint8ClampedArray(imgData.data),
                    imgData.width,
                    imgData.height
                );
                for (let i = 0; i < copy.data.length; i++) {
                    // Only add noise to color channels (R,G,B,A)
                    copy.data[i] = Math.min(255, Math.max(0, copy.data[i] + Math.floor(Math.random() * 6) - 3));
                }
                return copy;
            }

            // Patch getImageData
            const origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
            CanvasRenderingContext2D.prototype.getImageData = function(x, y, w, h) {
                const imgData = origGetImageData.apply(this, arguments);
                return noisyImageData(imgData);
            };

            // Patch toDataURL
            const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
            HTMLCanvasElement.prototype.toDataURL = function() {
                const ctx = this.getContext("2d");
                if (ctx) {
                    const w = this.width, h = this.height;
                    const imgData = ctx.getImageData(0, 0, w, h);
                    const noisy = noisyImageData(imgData);
                    ctx.putImageData(noisy, 0, 0);
                    const result = origToDataURL.apply(this, arguments);
                    ctx.putImageData(imgData, 0, 0); // Restore original
                    return result;
                }
                return origToDataURL.apply(this, arguments);
            };

            // Patch toBlob (for extra stealth)
            const origToBlob = HTMLCanvasElement.prototype.toBlob;
            HTMLCanvasElement.prototype.toBlob = function() {
                const ctx = this.getContext("2d");
                if (ctx) {
                    const w = this.width, h = this.height;
                    const imgData = ctx.getImageData(0, 0, w, h);
                    const noisy = noisyImageData(imgData);
                    ctx.putImageData(noisy, 0, 0);
                    const args = arguments;
                    const restore = () => ctx.putImageData(imgData, 0, 0);
                    setTimeout(restore, 50);
                    return origToBlob.apply(this, args);
                }
                return origToBlob.apply(this, arguments);
            };
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)
    
    def inject_useragentdata_kill(self):
        script = r"""
        (() => {
          const undef = undefined;

          function nukeUAData(ctx) {
            try {
              // 1) Replace Navigator.prototype getter when possible
              const P = ctx.Navigator && ctx.Navigator.prototype;
              if (P) {
                const d = Object.getOwnPropertyDescriptor(P, "userAgentData");
                if (!d || d.configurable) {
                  Object.defineProperty(P, "userAgentData", { get: () => undef, configurable: false });
                }
              }

              // 2) Also override on the INSTANCE
              try { Object.defineProperty(ctx.navigator, "userAgentData", { get: () => undef, configurable: false }); } catch (e) {}

              // 3) If object exists, neuter its prototype
              try {
                const UAP = ctx.NavigatorUAData && ctx.NavigatorUAData.prototype;
                if (UAP) {
                  const emptyArr = Object.freeze([]), emptyStr = "";
                  const pairs = [
                    ["brands", emptyArr], ["fullVersionList", emptyArr],
                    ["mobile", false], ["platform", emptyStr], ["platformVersion", emptyStr],
                    ["architecture", emptyStr], ["bitness", emptyStr], ["model", emptyStr],
                    ["uaFullVersion", emptyStr], ["formFactor", emptyArr]
                  ];
                  for (const [k, v] of pairs) {
                    try { Object.defineProperty(UAP, k, { get: () => v, configurable: true }); } catch (e) {}
                  }
                  try { Object.defineProperty(UAP, "getHighEntropyValues", { value: () => Promise.resolve({}), configurable: true }); } catch (e) {}
                }
              } catch (e) {}

              // 4) Hide the constructor for feature sniffing
              try { Object.defineProperty(ctx, "NavigatorUAData", { value: undef, configurable: false }); } catch (e) {}
            } catch (e) {}
          }

          // top window
          nukeUAData(window);

          // new iframes (about:blank/srcdoc included)
          new MutationObserver(muts => {
            for (const m of muts) for (const n of m.addedNodes) {
              if (n && n.tagName === "IFRAME") {
                try { n.contentWindow && nukeUAData(n.contentWindow); } catch (e) {}
              }
            }
          }).observe(document.documentElement, { childList: true, subtree: true });
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation, subframes=True)

    def inject_navigator_prototype_spoof(self):
        # final surface values (Firefox 78 on Linux; vendor empty)
        script = r"""
        (() => {
          const UA = "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0";

          const defs = {
            userAgent: UA,
            appVersion: "5.0 (X11)",
            platform: "Linux x86_64",
            vendor: "",
            languages: Object.freeze(["en-US","en"]),
            language: "en-US",
            webdriver: false,
            doNotTrack: "1",
            maxTouchPoints: 0,
            hardwareConcurrency: 4,
            deviceMemory: 4
          };

          for (const [k,v] of Object.entries(defs)) {
            try { Object.defineProperty(Navigator.prototype, k, { get: () => v, configurable: true }); } catch(_){}
          }

          // Also patch the instance in case someone cached descriptors
          try {
            for (const [k,v] of Object.entries(defs)) {
              Object.defineProperty(navigator, k, { get: () => v, configurable: true });
            }
          } catch(_){}
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation, subframes=True)
# --- END: UA-CH + Navigator prototype mixin ---

    def inject_stealth_profile(self):
        script = """
        (() => {
            const spoofUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101 Firefox/78.0";

            const spoofedNavigator = {
                userAgent: spoofUA,
                appVersion: "5.0 (Windows NT 10.0)",
                platform: "Win32",
                vendor: "",
                language: "en-US",
                languages: ["en-US", "en"],
                webdriver: false,
                doNotTrack: "1",
                maxTouchPoints: 0,
                deviceMemory: 4,
                hardwareConcurrency: 4,
                connection: undefined,
                bluetooth: undefined
            };

            for (const [key, value] of Object.entries(spoofedNavigator)) {
                try {
                    Object.defineProperty(navigator, key, {
                        get: () => value,
                        configurable: true
                    });
                } catch (_) {}
            }

            try {
                navigator.__defineGetter__('userAgentData', () => undefined);
                Object.defineProperty(window, 'chrome', { get: () => undefined });
                Object.defineProperty(document, 'cookie', {
                    get: () => '',
                    set: () => {},
                    configurable: true
                });
            } catch (_) {}

            const fakeHeaders = {
                'sec-ch-ua': '',
                'sec-ch-ua-platform': '',
                'sec-ch-ua-mobile': '',
                'user-agent': spoofUA,
                'referer': '',
                'referrer-policy': 'no-referrer'
            };

            const patchHeaders = (headers) => {
                for (const h in fakeHeaders) {
                    try { headers.set(h, fakeHeaders[h]); } catch (_) {}
                }
            };

            const originalFetch = window.fetch;
            window.fetch = function(resource, init = {}) {
                init.headers = new Headers(init.headers || {});
                patchHeaders(init.headers);
                init.referrer = '';
                init.referrerPolicy = 'no-referrer';
                return originalFetch(resource, init);
            };

            const originalOpen = XMLHttpRequest.prototype.open;
            XMLHttpRequest.prototype.open = function(...args) {
                this.addEventListener("readystatechange", function() {
                    if (this.readyState === 1) {
                        try {
                            for (const h in fakeHeaders) {
                                this.setRequestHeader(h, fakeHeaders[h]);
                            }
                        } catch (_) {}
                    }
                });
                return originalOpen.apply(this, args);
            };

            console.log("[Darkelf StealthInjector] Spoofing applied.");
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)

    def _inject_font_protection(self):
        js = """
        // [DarkelfAI] Font fingerprinting protection with .onion whitelist

        (function() {
            const isOnion = window.location.hostname.endsWith(".onion");
            if (isOnion) {
                console.warn("[DarkelfAI] .onion site detected — skipping font spoofing.");
                return;
            }

            // Slight noise added to disrupt precise fingerprinting
            const randomize = (val, factor = 0.03) => val + (Math.random() * val * factor);

            // Override measureText to return slightly randomized width
            const originalMeasureText = CanvasRenderingContext2D.prototype.measureText;
            CanvasRenderingContext2D.prototype.measureText = function(text) {
                const metrics = originalMeasureText.call(this, text);
                metrics.width = randomize(metrics.width);
                return metrics;
            };

            // Spoof getComputedStyle to alter only font properties
            const originalGetComputedStyle = window.getComputedStyle;
            window.getComputedStyle = function(...args) {
                const style = originalGetComputedStyle.apply(this, args);
                return new Proxy(style, {
                    get(target, prop) {
                        if (typeof prop === 'string' && prop.toLowerCase().includes('font')) {
                            return '16px "Noto Sans"';
                        }
                        return target[prop];
                    }
                });
            };

            // Slightly randomized offsetWidth/offsetHeight
            const offsetNoise = () => Math.floor(90 + Math.random() * 10);
            Object.defineProperty(HTMLElement.prototype, 'offsetWidth', {
                get: function () { return offsetNoise(); },
                configurable: true
            });
            Object.defineProperty(HTMLElement.prototype, 'offsetHeight', {
                get: function () { return offsetNoise(); },
                configurable: true
            });

            console.log('[DarkelfAI] Soft font fingerprinting vectors spoofed.');
        })();
        """
        self.inject_script(js, injection_point=QWebEngineScript.DocumentCreation)
        
    def spoof_font_loading_checks(self):
        script = """
        (function() {
            const originalCheck = document.fonts.check;
            document.fonts.check = function(...args) {
                return true;
            };
            const originalLoad = document.fonts.load;
            document.fonts.load = function(...args) {
                return new Promise(resolve => {
                    setTimeout(() => resolve(["Arial"]), Math.random() * 80 + 50);
                });
            };
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)
        
    def block_webgpu_api(self):
        script = """
        (function() {
            Object.defineProperty(navigator, 'gpu', {
                get: () => undefined
            });
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)
        
    def harden_webworkers(self):
        script = """
        (function() {
            const originalWorker = window.Worker;
            window.Worker = new Proxy(originalWorker, {
                construct(target, args) {
                    try {
                        if (args[0] instanceof Blob) {
                            const codeURL = URL.createObjectURL(args[0]);
                            return new target(codeURL);
                        }
                    } catch (e) {}
                    return new target(...args);
                }
            });
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)
        
    def block_cookie_banners(self):
        script = """
        (() => {
            const selectors = [
                '[id*="cookie"]',
                '[class*="cookie"]',
                '[aria-label*="cookie"]',
                '[role="dialog"]',
                '[role="alertdialog"]',
                'div[class*="consent"]',
                'div[class*="banner"]',
                'div[class*="notice"]',
                'div[class*="gdpr"]',
                'div[class*="privacy"]',
                'div[class*="optin"]'
            ];

            const textTriggers = [
                /cookie/i,
                /consent/i,
                /gdpr/i,
                /privacy/i,
                /we use/i,
                /accept.*cookies/i,
                /manage.*preferences/i,
                /your.*choices/i
            ];

            const buttonDenyRegex = /\\b(reject|deny|refuse|disagree|decline|only necessary|essential only)\\b/i;

            function isCookieBanner(el) {
                if (!el || !el.tagName) return false;
                const txt = (el.textContent || '').trim().toLowerCase();
                return textTriggers.some(re => re.test(txt));
            }

            function removeElement(el) {
                try {
                    el.remove?.();
                    if (el.parentNode) el.parentNode.removeChild(el);
                } catch (_) {}
            }

            function clickDenyButtons() {
                try {
                    const all = document.querySelectorAll('button, a, input[type="button"]');
                    for (const el of all) {
                        const txt = (el.textContent || el.value || '').toLowerCase();
                        if (buttonDenyRegex.test(txt)) {
                            el.click?.();
                        }
                    }
                } catch (_) {}
            }

            function removeBanners() {
                try {
                    const all = new Set();

                    for (const sel of selectors) {
                        try {
                            document.querySelectorAll(sel).forEach(el => {
                                if (isCookieBanner(el)) all.add(el);
                            });
                        } catch (_) {}
                    }

                    for (const el of all) {
                        removeElement(el);
                    }

                    clickDenyButtons();
                } catch (_) {}
            }

            function shadowDOMScan(root) {
                try {
                    const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT, null, false);
                    while (walker.nextNode()) {
                        const node = walker.currentNode;
                        if (node.shadowRoot) {
                            removeBanners(node.shadowRoot);
                            shadowDOMScan(node.shadowRoot);
                        }
                    }
                } catch (_) {}
            }

            function safeIdle(cb) {
                if ('requestIdleCallback' in window) {
                    requestIdleCallback(cb, { timeout: 300 });
                } else {
                    setTimeout(cb, 100);
                }
            }

            function harden() {
                try {
                    removeBanners();
                    shadowDOMScan(document);

                    const observer = new MutationObserver(() => {
                        safeIdle(() => {
                            removeBanners();
                            shadowDOMScan(document);
                        });
                    });

                    observer.observe(document.documentElement, {
                        childList: true,
                        subtree: true
                    });
                } catch (_) {}
            }

            if (document.readyState === 'complete' || document.readyState === 'interactive') {
                safeIdle(harden);
            } else {
                window.addEventListener('DOMContentLoaded', () => safeIdle(harden));
            }
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)

    def block_webauthn(self):
        script = """
        (function() {
            if (navigator.credentials) {
                navigator.credentials.get = function() {
                    return Promise.reject("WebAuthn disabled for security.");
                };
                navigator.credentials.create = function() {
                    return Promise.reject("WebAuthn creation disabled.");
                };
            }
            if (window.PublicKeyCredential) {
                window.PublicKeyCredential = undefined;
            }
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)
        
    def block_web_bluetooth(self):
        script = """
        (function() {
            if ('bluetooth' in navigator) {
                Object.defineProperty(navigator, 'bluetooth', {
                    get: () => ({
                        requestDevice: () => Promise.reject('Web Bluetooth disabled.')
                    })
                });
            }
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)
        
    def block_speech_synthesis(self):
        script = """
        (function() {
            if ('speechSynthesis' in window) {
                window.speechSynthesis.getVoices = function() {
                    return [];
                };
                Object.defineProperty(window, 'speechSynthesis', {
                    get: () => ({
                        getVoices: () => []
                    })
                });
            }
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)
        
    def clamp_performance_timers(self):
        script = """
        (function() {
            const originalNow = performance.now;
            performance.now = function() {
                return Math.floor(originalNow.call(performance) / 10) * 10;
            };
            const originalDateNow = Date.now;
            Date.now = function() {
                return Math.floor(originalDateNow() / 10) * 10;
            };
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)
        
    def spoof_audio_fingerprint_response(self):
        script = """
        (function() {
            const originalGetChannelData = AudioBuffer.prototype.getChannelData;
            AudioBuffer.prototype.getChannelData = function() {
                const data = originalGetChannelData.call(this);
                const spoofed = new Float32Array(data.length);
                for (let i = 0; i < data.length; i++) {
                    spoofed[i] = 0.5;  // static waveform to defeat fingerprinting
                }
                return spoofed;
            };
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)

    def block_fedcm_api(self):
        script = """
        (function() {
            if (navigator && 'identity' in navigator) {
                navigator.identity = undefined;
            }
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)
        
    def patch_youtube_compatibility(self):
        script = """
        (function() {
            const override = () => {
                const hostname = window.location.hostname;
                if (hostname.includes("youtube.com") || hostname.includes("ytimg.com")) {

                    // Restore AudioContext
                    if (typeof AudioContext === 'undefined' && typeof webkitAudioContext !== 'undefined') {
                        window.AudioContext = webkitAudioContext;
                    }   

                    // Fake Permissions API for mic/camera
                    if (navigator.permissions && navigator.permissions.query) {
                        const originalQuery = navigator.permissions.query.bind(navigator.permissions);
                            navigator.permissions.query = function(param) {
                            if (param && (param.name === 'microphone' || param.name === 'camera')) {
                                return Promise.resolve({ state: 'denied' });
                            }
                            return originalQuery(param);
                        };
                    }

                    // Stub WebAuthn
                    if (!window.PublicKeyCredential) {
                        window.PublicKeyCredential = function() {};
                    }

                    // Fingerprint resistance: spoof plugins and webdriver
                    Object.defineProperty(navigator, 'webdriver', { get: () => false });
                    Object.defineProperty(navigator, 'plugins', {
                        get: () => [1, 2, 3], // fake plugin list
                    });
                    Object.defineProperty(navigator, 'languages', {
                        get: () => ['en-US', 'en'],
                    });

                    // Force autoplay: mute video early
                    const muteVideos = () => {
                        const vids = document.querySelectorAll('video');
                        vids.forEach(v => {
                            v.muted = true;
                            v.autoplay = true;
                            v.playsInline = true;
                            v.play().catch(() => {});
                        });
                    };
                    document.addEventListener('DOMContentLoaded', muteVideos);
                    setTimeout(muteVideos, 300); // backup

                }
            };

            if (document.readyState === 'loading') {
                document.addEventListener('readystatechange', () => {
                    if (document.readyState === 'interactive') override();
                });
            } else {
                override();
            }
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)

    def spoof_language_headers(self):
        script = """
        (function() {
            Object.defineProperty(navigator, 'language', {
                get: function () { return 'en-US'; }
            });
            Object.defineProperty(navigator, 'languages', {
                get: function () { return ['en-US', 'en']; }
            });
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)
        
    def hide_webdriver_flag(self):
        script = """
        (function() {
            Object.defineProperty(navigator, 'webdriver', {
                get: () => false
            });
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)

    def block_idle_detector(self):
        script = """
        (function() {
            if ('IdleDetector' in window) {
                window.IdleDetector = function() {
                    throw new Error("IdleDetector blocked for privacy reasons.");
                };
            }
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)

    def spoof_navigator_basics(self):
        script = """
        (function() {
            Object.defineProperty(navigator, "webdriver", {
                get: () => false,
                configurable: true
            });
            Object.defineProperty(navigator, "doNotTrack", {
                get: () => "1",
                configurable: true
            });
            Object.defineProperty(navigator, "maxTouchPoints", {
                get: () => 1,
                configurable: true
            });
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)

    def block_window_chrome(self):
        script = """
        (function() {
            Object.defineProperty(window, 'chrome', {
                value: undefined,
                configurable: true
            });
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)
   
    def spoof_permissions_api(self):
        script = """
        (function() {
            if (navigator.permissions && navigator.permissions.query) {
                navigator.permissions.query = function(params) {
                    return Promise.resolve({ state: 'denied' });
                };
            }
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)
   
    def fuzz_timing_functions(self):
        script = """
        (function() {
            performance.now = () => Math.floor(Math.random() * 50) + 1;
            Date.now = () => Math.floor(new Date().getTime() / 1000) * 1000;
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)
    
    def spoof_storage_estimate(self):
        script = """
        (function() {
            if (navigator.storage && navigator.storage.estimate) {
                navigator.storage.estimate = function() {
                    return Promise.resolve({ quota: 120000000, usage: 50000000 });
                };
            }
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)

    def block_fontfaceset_api(self):
        script = """
        (function() {
            try {
                document.fonts = {
                    ready: Promise.resolve(),
                    check: () => false,
                    load: () => Promise.reject("Blocked"),
                    values: () => [],
                    size: 0
                };
            } catch (e) {
                console.warn("FontFaceSet override failed", e);
            }
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)

    def block_eval_and_websockets(self):
        script = """
        (function() {
            // Monitor eval() usage, but do not block it
            const originalEval = window.eval;
            window.eval = function(code) {
                try {
                    if (typeof code === 'string' && code.length > 0) {
                        console.debug("eval() used — allowing:", code.slice(0, 100));
                    }
                    return originalEval(code);
                } catch (e) {
                    console.warn("eval() error:", e);
                    return undefined;
                }
            };

            // Light filter for suspicious Function constructor usage
            const OriginalFunction = Function;
            window.Function = function(...args) {
                const code = args.join(' ');
                if (code.includes('eval') || code.includes('setTimeout')) {
                    console.debug("Suspicious Function constructor blocked:", code.slice(0, 100));
                    return function() {};  // return a dummy
                }
                return OriginalFunction(...args);
            };

            // Safe WebSocket dummy that won't throw or crash detection
            const DummySocket = function(url, protocols) {
                console.debug("WebSocket attempt intercepted:", url);
                return {
                    send: () => {},
                    close: () => {},
                    addEventListener: () => {},
                    removeEventListener: () => {},
                    readyState: 3,  // CLOSED
                    bufferedAmount: 0
                };
            };

            // Only override WebSocket if it's present
            if ('WebSocket' in window) {
                window.WebSocket = DummySocket;
                Object.defineProperty(window, 'WebSocket', {
                    value: DummySocket,
                    writable: false,
                    configurable: true
                });
            }
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)

    def block_cookie_beacon_getstats(self):
        script = """
        (function() {
            // Block document.cookie (read/write)
            Object.defineProperty(document, 'cookie', {
                get: function() {
                    return "";
                },
                set: function(_) {
                    console.warn("Blocked attempt to set document.cookie");
                },
                configurable: true
            });

            // Block navigator.sendBeacon
            if (navigator.sendBeacon) {
                navigator.sendBeacon = function() {
                    console.warn("sendBeacon blocked");
                    return false;
                };
            }

            // Block WebRTC getStats (used in fingerprinting)
            if (window.RTCPeerConnection) {
                const original = RTCPeerConnection.prototype.getStats;
                RTCPeerConnection.prototype.getStats = function() {
                    console.warn("RTCPeerConnection.getStats blocked");
                    return Promise.resolve({});
                };
            }
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)
        
    def block_audio_context(self):
        script = """
        (function() {
            try {
                // Disable AudioContext completely
                window.AudioContext = undefined;
                window.webkitAudioContext = undefined;

                // If already instantiated, override methods
                const noop = function() {};

                if (typeof OfflineAudioContext !== "undefined") {
                    OfflineAudioContext.prototype.startRendering = noop;
                    OfflineAudioContext.prototype.suspend = noop;
                }

                if (typeof AudioContext !== "undefined") {
                    AudioContext.prototype.createAnalyser = function() {
                        return {
                            getFloatFrequencyData: function(array) {
                                for (let i = 0; i < array.length; i++) {
                                    array[i] = -100 + Math.random();  // Fake data
                                }
                            }
                        };
                    };
                }
            } catch (e) {
                console.warn("AudioContext block failed:", e);
            }
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)

    def spoof_device_memory(self):
        script = """
        (function() {
            Object.defineProperty(navigator, 'deviceMemory', {
                get: () => 4,  // Common value in real browsers
                configurable: true
            });
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)
        
    def disable_pointer_detection(self):
        script = """
        (function() {
            // Remove touch support
            Object.defineProperty(navigator, 'maxTouchPoints', {
                get: () => 0,
                configurable: true
            });

            // Override pointer/touch event support checks
            if ('ontouchstart' in window) {
                delete window.ontouchstart;
            }

            // Disable pointer media queries
            const style = document.createElement('style');
            style.innerHTML = `
                @media (pointer: coarse), (hover: none) {
                    body::before {
                        content: none !important;
                    }
                }
            `;
            document.head.appendChild(style);
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)

    def spoof_battery_api(self):
        script = """
        (function() {
            if ('getBattery' in navigator) {
                navigator.getBattery = function() {
                    return Promise.resolve({
                        charging: true,
                        chargingTime: 0,
                        dischargingTime: Infinity,
                        level: 1.0,
                        onchargingchange: null,
                        onchargingtimechange: null,
                        ondischargingtimechange: null,
                        onlevelchange: null,
                        addEventListener: () => {},
                        removeEventListener: () => {}
                    });
                };
            }
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)
        
    def spoof_network_connection(self):
        script = """
        (function() {
            if ('connection' in navigator) {
                Object.defineProperty(navigator, 'connection', {
                    get: () => ({
                        downlink: 10,
                        effectiveType: '4g',
                        rtt: 50,
                        saveData: false,
                        type: 'wifi',
                        onchange: null,
                        addEventListener: () => {},
                        removeEventListener: () => {}
                    }),
                    configurable: true
                });
            }
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)

    def spoof_plugins_and_mimetypes(self):
        script = """
        (function() {
            Object.defineProperty(navigator, 'plugins', {
                get: () => ({
                    length: 0,
                    item: () => null,
                    namedItem: () => null
                }),
                configurable: true
            });

            Object.defineProperty(navigator, 'mimeTypes', {
                get: () => ({
                    length: 0,
                    item: () => null,
                    namedItem: () => null
                }),
                configurable: true
            });
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)

    def spoof_timezone(self):
        script = """
        (function() {
            const spoofedOffset = 0; // UTC

            Object.defineProperty(Intl.DateTimeFormat.prototype, 'resolvedOptions', {
                value: function() {
                    return {
                        timeZone: "UTC",
                        locale: "en-US"
                    };
                },
                configurable: true
            });

            const originalGetTimezoneOffset = Date.prototype.getTimezoneOffset;
            Date.prototype.getTimezoneOffset = function() {
                return spoofedOffset;
            };
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)

    def spoof_media_queries(self):
        script = """
        (function() {
            const fakeMatchMedia = (query) => {
                return {
                    matches: false,
                    media: query,
                    onchange: null,
                    addListener: () => {},
                    removeListener: () => {},
                    addEventListener: () => {},
                    removeEventListener: () => {},
                    dispatchEvent: () => false
                };
            };
            window.matchMedia = fakeMatchMedia;
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)

    def block_referrer_headers(self):
        script = """
        (function() {
            const originalOpen = XMLHttpRequest.prototype.open;
            XMLHttpRequest.prototype.open = function(method, url) {
                this.addEventListener('readystatechange', function() {
                    if (this.readyState === 1) {
                        try {
                            this.setRequestHeader('Referer', '');
                            this.setRequestHeader('Referrer-Policy', 'no-referrer');
                        } catch (e) {}
                    }
                });
                return originalOpen.apply(this, arguments);
            };

            const originalFetch = window.fetch;
            window.fetch = function(resource, init = {}) {
                init.referrer = '';
                init.referrerPolicy = 'no-referrer';
                init.headers = Object.assign({}, init.headers || {}, {
                    'Referer': '',
                    'Referrer-Policy': 'no-referrer'
                });
                return originalFetch(resource, init);
            };

            document.addEventListener('DOMContentLoaded', function() {
                const meta = document.createElement('meta');
                meta.name = 'referrer';
                meta.content = 'no-referrer';
                document.head.appendChild(meta);
            });
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)
        
    def spoof_user_agent(self):
        script = """
        (function() {
            const spoofedUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101 Firefox/78.0";

            Object.defineProperty(navigator, 'userAgent', {
                get: () => spoofedUA,
                configurable: true
            });
            Object.defineProperty(navigator, 'appVersion', {
                get: () => spoofedUA,
                configurable: true
            });
            Object.defineProperty(navigator, 'platform', {
                get: () => 'Win32',
                configurable: true
            });
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)
        
    def block_shadow_dom_inspection(self):
        script = """
        (function () {
            const originalAttachShadow = Element.prototype.attachShadow;
            Element.prototype.attachShadow = function(init) {
                init.mode = 'closed';  // Force closed mode
                return originalAttachShadow.call(this, init);
            };
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)

    def block_tracking_requests(self):
        script = """
        (function () {
            const suspiciousPatterns = ['tracker', 'analytics', 'collect', 'pixel'];

            const shouldBlock = (url) => {
                return suspiciousPatterns.some(p => url.includes(p));
            };

            const originalXHRopen = XMLHttpRequest.prototype.open;
            XMLHttpRequest.prototype.open = function(method, url) {
                if (shouldBlock(url)) {
                    console.warn('Blocked XHR to:', url);
                    return;
                }
                return originalXHRopen.apply(this, arguments);
            };

            const originalFetch = window.fetch;
            window.fetch = function(...args) {
                const url = args[0];
                if (typeof url === 'string' && shouldBlock(url)) {
                    console.warn('Blocked fetch to:', url);
                    return new Promise(() => {}); // Never resolves
                }
                return originalFetch.apply(this, args);
            };
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)

    def block_webrtc_sdp_logging(self):
        script = """
        (function() {
            if (!window.RTCPeerConnection) return;

            const OriginalRTCPeerConnection = window.RTCPeerConnection;
            window.RTCPeerConnection = function(...args) {
                const pc = new OriginalRTCPeerConnection(...args);

                const wrap = (method) => {
                    if (pc[method]) {
                        const original = pc[method].bind(pc);
                        pc[method] = async function(...mArgs) {
                            const result = await original(...mArgs);
                            if (result && result.sdp) {
                                result.sdp = result.sdp.replace(/a=candidate:.+\\r\\n/g, '');
                                result.sdp = result.sdp.replace(/ice-ufrag:.+\\r\\n/g, '');
                                result.sdp = result.sdp.replace(/ice-pwd:.+\\r\\n/g, '');
                            }
                            return result;
                        };
                    }
                };

                wrap("createOffer");
                wrap("createAnswer");

                return pc;
            };
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)
        
    def block_supercookies(self):
        script = """
        (function() {
            try {
                // Nullify openDatabase (WebSQL)
                try { delete window.openDatabase; } catch (e) {}
                Object.defineProperty(window, 'openDatabase', {
                    value: null,
                    writable: false,
                    configurable: false
                });

                // Nullify localStorage
                try { delete window.localStorage; } catch (e) {}
                Object.defineProperty(window, 'localStorage', {
                    value: null,
                    writable: false,
                    configurable: false
                });

                // Nullify sessionStorage
                try { delete window.sessionStorage; } catch (e) {}
                Object.defineProperty(window, 'sessionStorage', {
                    value: null,
                    writable: false,
                    configurable: false
                });

                // Nullify indexedDB
                try { delete window.indexedDB; } catch (e) {}
                Object.defineProperty(window, 'indexedDB', {
                    value: null,
                    writable: false,
                    configurable: false
                });

                // Nullify cookies
                Object.defineProperty(document, 'cookie', {
                    get: function() { return ""; },
                    set: function() {},
                    configurable: false
                });

                // Nullify BroadcastChannel
                try { delete window.BroadcastChannel; } catch (e) {}
                Object.defineProperty(window, 'BroadcastChannel', {
                    value: null,
                    writable: false,
                    configurable: false
                });

                // Nullify SharedWorker
                try { delete window.SharedWorker; } catch (e) {}
                Object.defineProperty(window, 'SharedWorker', {
                    value: null,
                    writable: false,
                    configurable: false
                });

                // Nullify ServiceWorker
                if ('serviceWorker' in navigator) {
                    Object.defineProperty(navigator, 'serviceWorker', {
                        value: null,
                        writable: false,
                        configurable: false
                    });
                }

                // Nullify CacheStorage
                if ('caches' in window) {
                    Object.defineProperty(window, 'caches', {
                        value: null,
                        writable: false,
                        configurable: false
                    });
                }

                // Nullify FileSystem API (Chrome legacy supercookie)
                if ('webkitRequestFileSystem' in window) {
                    window.webkitRequestFileSystem = null;
                    window.requestFileSystem = null;
                }

                // Nullify persistent storage access
                if ('storage' in navigator && 'persist' in navigator.storage) {
                    Object.defineProperty(navigator, 'storage', {
                        value: null,
                        writable: false,
                        configurable: false
                    });
                }

            } catch (e) {
                console.warn("Supercookie nullification error:", e);
            }
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)

    def protect_fingerprinting(self):
        script = """
        (function() {
            // === Canvas Fingerprinting Randomization ===
            const originalGetImageData = CanvasRenderingContext2D.prototype.getImageData;
            CanvasRenderingContext2D.prototype.getImageData = function(x, y, w, h) {
                const data = originalGetImageData.apply(this, arguments);
                for (let i = 0; i < data.data.length; i += 4) {
                    data.data[i]     += Math.floor(Math.random() * 10) - 5;
                    data.data[i + 1] += Math.floor(Math.random() * 10) - 5;
                    data.data[i + 2] += Math.floor(Math.random() * 10) - 5;
                }
                return data;
            };

            const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
            HTMLCanvasElement.prototype.toDataURL = function() {
                const result = originalToDataURL.apply(this, arguments);
                return result + "#noise";
            };

            const originalToBlob = HTMLCanvasElement.prototype.toBlob;
            HTMLCanvasElement.prototype.toBlob = function(callback, ...args) {
                return originalToBlob.call(this, function(blob) {
                    callback(blob);
                }, ...args);
            };

            // === WebGL Spoofing ===
            const originalGetParameter = WebGLRenderingContext.prototype.getParameter;
            WebGLRenderingContext.prototype.getParameter = function(param) {
                if (param === 37445) return "Intel Inc.";
                if (param === 37446) return "Intel Iris OpenGL Engine";
                return originalGetParameter.apply(this, arguments);
            };

            // === Font Fingerprinting Spoofing ===
            const originalMeasureText = CanvasRenderingContext2D.prototype.measureText;
            CanvasRenderingContext2D.prototype.measureText = function(text) {
                const metrics = originalMeasureText.apply(this, arguments);
                metrics.width += Math.random(); // subpixel alteration
                return metrics;
            };

            const originalComputedStyle = window.getComputedStyle;
            window.getComputedStyle = function(el, pseudo) {
                const style = originalComputedStyle.call(this, el, pseudo);
                Object.defineProperty(style, "fontFamily", {
                    get: function() { return "Arial, sans-serif"; }
                });
                return style;
            };

            // === Audio Fingerprinting Obfuscation ===
            const originalCreateAnalyser = AudioContext.prototype.createAnalyser;
            AudioContext.prototype.createAnalyser = function() {
                const analyser = originalCreateAnalyser.apply(this, arguments);
                const original = analyser.getFloatFrequencyData;
                analyser.getFloatFrequencyData = function(array) {
                    for (let i = 0; i < array.length; i++) {
                        array[i] = -100 + Math.random() * 5;
                    }
                    return original.apply(this, arguments);
                };
                return analyser;
            };

            // === Screen/Locale/Timezone Spoofing ===
            Object.defineProperty(navigator, "language", {
                get: () => ["en-US", "fr-FR", "de-DE"][Math.floor(Math.random() * 3)]
            });
            Object.defineProperty(navigator, "languages", {
                get: () => ["en-US", "en"]
            });

            Object.defineProperty(screen, "width", {
                get: () => 1280 + Math.floor(Math.random() * 160)
            });
            Object.defineProperty(screen, "height", {
                get: () => 720 + Math.floor(Math.random() * 160)
            });
            Object.defineProperty(screen, "colorDepth", {
                get: () => 24
            });

            Object.defineProperty(navigator, "hardwareConcurrency", {
                get: () => [2, 4, 8][Math.floor(Math.random() * 3)]
            });

            // === Timezone Spoofing ===
            const originalDateToString = Date.prototype.toString;
            Date.prototype.toString = function() {
                return originalDateToString.apply(new Date('1970-01-01T00:00:00Z'), arguments);
            };

            // === Media Devices ===
            Object.defineProperty(navigator, "mediaDevices", {
                get: () => undefined
            });
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)
        
    def protect_fonts(self):
        script = """
        (function() {
            const original = CanvasRenderingContext2D.prototype.measureText;
            CanvasRenderingContext2D.prototype.measureText = function(text) {
                const metrics = original.call(this, text);
                metrics.width += (Math.random() * 5 - 2.5);
                return metrics;
            };

            const originalComputed = window.getComputedStyle;
            window.getComputedStyle = function(el, pseudo) {
                const cs = originalComputed.call(window, el, pseudo);
                const modified = new Proxy(cs, {
                    get(target, prop) {
                        if (prop === "fontFamily") return "Arial";
                        return Reflect.get(target, prop);
                    }
                });
                return modified;
            };
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)

    def spoof_canvas_api(self):
        # If HARDEN_JS blocked canvas/WebGL, do nothing to avoid re-adding methods.
        script = """
        (function(){
        if (window.__DARKELF_BLOCK_CANVAS__ || window.__DARKELF_BLOCK_CANVAS_WEBGL__) {
            return; // HARDEN_JS active: don't re-wrap canvas APIs
        }
        // Intentionally left empty to avoid reintroducing toDataURL/toBlob.
        // (If you ever want legacy smudge logic again, add it below this guard.)
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)

    def stealth_webrtc_block(self):
        script = """
        (() => {
            const block = (target, key) => {
                try {
                    Object.defineProperty(target, key, {
                        get: () => undefined,
                        set: () => {},
                        configurable: false
                    });
                    delete target[key];
                } catch (e) {
                    // Silently ignore expected errors (e.g. non-configurable)
                }
            };

            const targets = [
                [window, 'RTCPeerConnection'],
                [window, 'webkitRTCPeerConnection'],
                [window, 'mozRTCPeerConnection'],
                [window, 'RTCDataChannel'],
                [navigator, 'mozRTCPeerConnection'],
                [navigator, 'mediaDevices']
            ];

            targets.forEach(([obj, key]) => block(obj, key));

            // Iframe defense
            new MutationObserver((muts) => {
                for (const m of muts) {
                    m.addedNodes.forEach((node) => {
                        if (node.tagName === 'IFRAME') {
                            try {
                                const w = node.contentWindow;
                                targets.forEach(([obj, key]) => block(w, key));
                                targets.forEach(([obj, key]) => block(w.navigator, key));
                            } catch (e) {}
                        }
                    });
                }
            }).observe(document, { childList: true, subtree: true });

            console.log('[DarkelfAI] WebRTC APIs neutralized.');
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)

    def block_etag_and_cache_tracking(self):
        script = """
        (function() {
            const originalOpen = XMLHttpRequest.prototype.open;
            XMLHttpRequest.prototype.open = function(method, url, async, user, password) {
                this.addEventListener('readystatechange', function() {
                    if (this.readyState === 1) {
                        try {
                            this.setRequestHeader('If-None-Match', '');
                            this.setRequestHeader('Cache-Control', 'no-store');
                            this.setRequestHeader('Pragma', 'no-cache');
                        } catch (e) {
                            console.warn("Header blocking error:", e);
                        }
                    }
                });
                return originalOpen.apply(this, arguments);
            };

            const originalFetch = window.fetch;
            window.fetch = function(resource, init = {}) {
                init.headers = Object.assign({}, init.headers || {}, {
                    'If-None-Match': '',
                    'Cache-Control': 'no-store',
                    'Pragma': 'no-cache'
                });
                return originalFetch(resource, init);
            };
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)

    def setup_csp(self):
        script = """
        (function() {
            const meta = document.createElement('meta');
            meta.httpEquiv = "Content-Security-Policy";
            meta.content = `
                default-src 'none';
                script-src 'self' 'unsafe-inline' https:;
                connect-src 'self' https: wss:;
                img-src 'self' data: https:;
                style-src 'self' 'unsafe-inline';
                font-src 'self' https:;
                media-src 'none';
                object-src 'none';
                frame-ancestors 'none';
                base-uri 'self';
                form-action 'self';
                upgrade-insecure-requests;
                block-all-mixed-content;
            `.replace(/\\s+/g, ' ').trim();
            document.head.appendChild(meta);
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation, subframes=False)

def build_profile(parent=None) -> QWebEngineProfile:
    profile = QWebEngineProfile("darkelf", parent)
    try:
        profile.setHttpCacheType(QWebEngineProfile.MemoryHttpCache)
        profile.setPersistentCookiesPolicy(QWebEngineProfile.NoPersistentCookies)
        profile.setSpellCheckEnabled(False)
        profile.setHttpUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101 Firefox/78.0")
    except Exception:
        pass
    return profile

def make_text_icon(char: str, fg: str = "#e6f0f7", size: int = 18) -> QIcon:
    pm = QPixmap(size, size)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing, True)
    p.setPen(QColor(fg))
    p.setFont(p.font())
    p.drawText(pm.rect(), Qt.AlignCenter, char)
    p.end()
    return QIcon(pm)

def apply_darkelf_menu_theme():
    qApp = QApplication.instance()
    if not qApp:
        return
    qApp.setStyleSheet(qApp.styleSheet() + f"""
        QMenu {{
            background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
                        stop:0 {THEME['surface']}, stop:1 {THEME['bg']});
            border: 1px solid {THEME['stroke']};
            border-radius: 12px;
            padding: 6px;
        }}
        QMenu::separator {{
            height: 1px;
            background: {THEME['stroke']};
            margin: 6px 8px;
        }}
        QMenu::item {{
            color: {THEME['text']};
            padding: 8px 12px;
            border-radius: 8px;
            background: transparent;
        }}
        QMenu::item:selected, QMenu::item:hover {{
            background: rgba(52,199,89,0.18);   /* Green highlight */
            color: #34C759;
            font-weight: bold;
        }}
        QMenu::item:disabled {{
            color: #7f8c8d;
            background: transparent;
        }}
        QMenu::icon {{ margin-right: 8px; }}
        QMenu::item {{
            cursor: pointer;
        }}
        QToolTip {{
            background: {THEME['surface']};
            color: {THEME['text']};
            border: 1px solid {THEME['stroke']};
            border-radius: 8px;
            padding: 6px 8px;
        }}
    """)
    
class HistoryDialog(QDialog):
    def __init__(self, items, parent=None):
        super().__init__(parent)
        self.setWindowTitle("History")
        self.setMinimumSize(600, 400)
        v = QVBoxLayout(self)
        self.list = QListWidget()
        self.list.addItems(items)
        v.addWidget(self.list)
        h = QHBoxLayout()
        clear_btn = QPushButton("Clear"); close_btn = QPushButton("Close")
        clear_btn.clicked.connect(self.accept); close_btn.clicked.connect(self.reject)
        h.addWidget(clear_btn); h.addWidget(close_btn)
        v.addLayout(h)

        # --- Dark theme styling like KEM768 ---
        self.setStyleSheet("""
            QDialog {
                background: #0b0f14;
                border-radius: 14px;
            }
            QListWidget {
                background: #11161d;
                color: #e6f0f7;
                border: 1px solid #1f2937;
                border-radius: 10px;
                selection-background-color: #34C759;
                selection-color: #11161d;
            }
            QPushButton {
                background: #34C759;
                color: #0b0f14;
                border: none;
                border-radius: 10px;
                padding: 10px 0;
                font-weight: bold;
            }
            QPushButton:hover {
                background: #1aa050;
                color: #fff;
            }
        """)

class Darkelf(QMainWindow):
    def __init__(self, start_url: str = "home"):
        super().__init__()
        print("[boot] Darkelf starting…")

        self.settings = EphemeralSettings()
        self.javascript_enabled = self.settings.value("javascript_enabled", True, type=bool)
        self.history_log = []
        self.tab_histories = {}

        # Tor default ON
        self.tor_network_enabled = self.settings.value("tor_network_enabled", True, type=bool)

        # Start Tor if enabled
        self.tor_process = None
        self.controller = None
        self.init_tor()

        # Profile + interceptors
        self.web_profile = self.build_web_profile()
        self._adblock = AdblockInterceptor(self)
        self._strip = StripClientHints(self)
        # Install anti-leak hardening, completely blocking iframe sec-ch-ua leaks
        DarkelfHardenedProfile.install(self.web_profile, remove_iframes=True)
        self._composite = CompositeInterceptor(self._adblock, self._strip, parent=self)
        self.web_profile.setUrlRequestInterceptor(self._composite)

        # UI
        self.init_ui()
        self.init_shortcuts()

        # First tab: homepage or provided URL
        self.create_new_tab(start_url)

    def build_web_profile(self):
        profile = QWebEngineProfile("darkelf", self)
        profile.setHttpCacheType(QWebEngineProfile.MemoryHttpCache)
        profile.setPersistentCookiesPolicy(QWebEngineProfile.NoPersistentCookies)
        profile.setSpellCheckEnabled(False)
        profile.setHttpUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101 Firefox/78.0")
        return profile
        
    # ====== Your TOR section (stem-based local tor) ======
    def init_tor(self):
        # start Tor if enabled, then try to route via QNetworkProxy + DNS env
        try:
            if getattr(self, "tor_network_enabled", False):
                self.start_tor()
                if self.is_tor_running():
                    self.configure_tor_proxy()
                    self.configure_tor_dns()
        except Exception as e:
            print("[Tor] init error:", e)

    def start_tor(self):
        try:
            if getattr(self, "tor_process", None):
                print("Tor is already running.")
                return

            tor_path = shutil.which("tor")
            if not tor_path or not os.path.exists(tor_path):
                QMessageBox.critical(self, "Tor Error", "Tor executable not found! Install it (e.g., 'brew install tor').")
                return

            # Prefer stem if available
            try:
                import stem.process
                from stem.control import Controller
            except Exception as e:
                print("[Tor] python-stem not available:", e)
                # Fallback: try to launch tor detached (no controller auth)
                self.tor_process = subprocess.Popen(
                    [tor_path, "SocksPort", "9052", "ControlPort", "9053", "DNSPort", "9054",
                     "AutomapHostsOnResolve", "1", "VirtualAddrNetworkIPv4", "10.192.0.0/10",
                     "CircuitBuildTimeout", "10", "MaxCircuitDirtiness", "180", "NewCircuitPeriod", "120",
                     "NumEntryGuards", "2", "AvoidDiskWrites", "1", "CookieAuthentication", "1",
                     "DataDirectory", "/tmp/darkelf-tor-data", "Log", "notice stdout"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                print("[Darkelf] Tor started (no stem controller).")
                return

            tor_config = {
                'SocksPort': '9052',
                'ControlPort': '9053',
                'DNSPort': '9054',
                'AutomapHostsOnResolve': '1',
                'VirtualAddrNetworkIPv4': '10.192.0.0/10',
                'CircuitBuildTimeout': '10',
                'MaxCircuitDirtiness': '180',
                'NewCircuitPeriod': '120',
                'NumEntryGuards': '2',
                'AvoidDiskWrites': '1',
                'CookieAuthentication': '1',
                'DataDirectory': '/tmp/darkelf-tor-data',
                'Log': 'notice stdout'
            }

            import stem.process
            from stem.control import Controller
            self.tor_process = stem.process.launch_tor_with_config(
                tor_cmd=tor_path, config=tor_config,
                init_msg_handler=lambda line: print("[tor]", line)
            )

            # Authenticate controller via cookie
            self.controller = Controller.from_port(port=9053)
            cookie_path = os.path.join('/tmp/darkelf-tor-data', 'control_auth_cookie')
            self.authenticate_cookie(self.controller, cookie_path=cookie_path)
            print("[Darkelf] Tor authenticated via cookie.")
            print("Tor started successfully.")

        except OSError as e:
            QMessageBox.critical(None, "Tor Error", f"Failed to start Tor: {e}")

    def authenticate_cookie(self, controller, cookie_path):
        try:
            with open(cookie_path, 'rb') as f:
                cookie = f.read()
            controller.authenticate(cookie)
        except Exception as e:
            print(f"[Darkelf] Tor cookie authentication failed: {e}")

    def is_tor_running(self):
        try:
            from stem.control import Controller
            with Controller.from_port(port=9053) as controller:
                controller.authenticate()
                print("Tor is running.")
                return True
        except Exception as e:
            print(f"Tor is not running: {e}")
            return False

    def configure_tor_proxy(self):
        # NOTE: QtWebEngine/Chromium primarily honors --proxy-server; this is a fallback.
        try:
            from PySide6.QtNetwork import QNetworkProxy
            proxy = QNetworkProxy(QNetworkProxy.Socks5Proxy, '127.0.0.1', 9052)
            QNetworkProxy.setApplicationProxy(proxy)
            print("Configured QNetworkProxy (SOCKS 127.0.0.1:9052).")
        except Exception as e:
            print("QNetworkProxy not available:", e)

    def configure_tor_dns(self):
        os.environ['DNSPORT'] = '127.0.0.1:9054'
        print("Configured Tor DNS env (DNSPORT=127.0.0.1:9054).")

    def stop_tor(self):
        try:
            if getattr(self, "tor_process", None):
                self.tor_process.terminate()
                self.tor_process = None
                print("Tor stopped.")
        except Exception:
            pass

    # ====== UI wiring from your snippet ======
    def init_shortcuts(self):
        QShortcut(QKeySequence("Ctrl+T" if sys.platform != 'darwin' else "Meta+T"),
                  self, self.create_new_tab)
        QShortcut(QKeySequence("Ctrl+W" if sys.platform != 'darwin' else "Meta+W"),
                  self, lambda: self.close_tab(self.tab_widget.currentIndex()))
        QShortcut(QKeySequence("Ctrl+R" if sys.platform != 'darwin' else "Meta+R"),
                  self, self.reload_page)
        QShortcut(QKeySequence("Alt+Left"),  self, self.go_back)
        QShortcut(QKeySequence("Alt+Right"), self, self.go_forward)
        QShortcut(QKeySequence("Ctrl++" if sys.platform != 'darwin' else "Meta++"),
                  self, self.zoom_in)
        QShortcut(QKeySequence("Ctrl+-" if sys.platform != 'darwin' else "Meta+-"),
                  self, self.zoom_out)
        QShortcut(QKeySequence("F11"), self, self.toggle_full_screen)
        QShortcut(QKeySequence("Ctrl+H" if sys.platform != 'darwin' else "Meta+H"),
                  self, self.view_history)

    def init_ui(self):
        self.setWindowTitle("Darkelf Browser")
        self.resize(1200, 800)
        self.tab_widget = QTabWidget()
        self.setCentralWidget(self.tab_widget)
        self.tab_widget.tabCloseRequested.connect(self.close_tab)
        self.tab_widget.setMovable(True)
        self.tab_widget.setTabsClosable(True)
        self.tab_widget.setStyleSheet(f"""
            QTabWidget::pane {{ border: 0; }}
            QTabBar::tab {{
                background: #333; color: #fff; padding: 5px 10px; border-radius: 10px; margin: 2px;
            }}
            QTabBar::tab:selected, QTabBar::tab:hover {{
                background: {THEME['accent']}; color: #000; border-radius: 10px;
            }}
        """)
        self.create_toolbar()
        self.create_menu_bar()

    def create_toolbar(self):
        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setFloatable(False)
        # --- Make navigation icons bigger ---
        toolbar.setIconSize(QSize(24, 24))  # Increased from 18x18 to 24x24
        toolbar.setContentsMargins(0,0,0,0)
        toolbar.setStyleSheet(f"""
            QToolBar {{
                background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 {THEME['surface']}, stop:1 {THEME['bg']});
                border: 0px; padding: 6px 10px; spacing: 6px;
            }}
            QToolBar::separator {{ background: {THEME['stroke']}; width: 1px; height: 24px; margin: 0 8px; }}
            QToolButton {{
                color: {THEME['text']}; background: rgba(255,255,255,0.02);
                border: 1px solid {THEME['stroke']}; border-radius: 10px; padding: 6px 10px;
                font-size: 18px;  /* Make any text bigger too */
            }}
            QToolButton:hover {{
                background: rgba(24,247,122,0.14);  /* Neon green bg */
                border-color: {THEME['accent']};    /* Green border */
                color: {THEME['accent']};           /* Icon/text green on hover */
            }}
            QToolButton:pressed {{
                background: rgba(24, 247, 122, 0.18); border-color: {THEME['accentDim']};
            }}
            QLineEdit#omni {{
                color: {THEME['text']}; background: {THEME['bg']}; border: 1px solid {THEME['stroke']};
                border-radius: 16px; padding: 8px 14px; selection-background-color: {THEME['accent']}; selection-color: #000;
            }}
            QLineEdit#omni:focus {{ border-color: {THEME['accent']}; }}
        """)

        # Increase icon size for navigation buttons
        nav_icon_size = 24  # Use same as toolbar icon size

        back_button    = self._btn(self.go_back, make_text_icon('◄', THEME['text'], nav_icon_size), "Back  (Alt+Left)")
        forward_button = self._btn(self.go_forward, make_text_icon('►', THEME['text'], nav_icon_size), "Forward  (Alt+Right)")
        reload_button  = self._btn(self.reload_page, make_text_icon('↺', THEME['text'], nav_icon_size), "Reload  (Ctrl+R)")
        home_button    = self._btn(self.load_homepage, make_text_icon('⏻', THEME['accent'], nav_icon_size), "Home")

        toolbar.addWidget(back_button); toolbar.addWidget(forward_button)
        toolbar.addWidget(reload_button); toolbar.addSeparator(); toolbar.addWidget(home_button)

        self.search_bar = QLineEdit(self); self.search_bar.setObjectName("omni")
        self.search_bar.setPlaceholderText("Search or enter URL")
        self.search_bar.returnPressed.connect(self.search_or_load_url)
        self.search_bar.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        toolbar.addWidget(self.search_bar)

        zoom_in_button  = self._btn(self.zoom_in,  make_text_icon('+', THEME['text'], nav_icon_size), "Zoom In  (Ctrl+=)")
        zoom_out_button = self._btn(self.zoom_out, make_text_icon('−', THEME['text'], nav_icon_size), "Zoom Out  (Ctrl+-)")
        full_button     = self._btn(self.toggle_full_screen, make_text_icon('⛶', THEME['text'], nav_icon_size), "Full Screen  (F11)")

        toolbar.addSeparator()
        toolbar.addWidget(zoom_out_button); toolbar.addWidget(zoom_in_button); toolbar.addWidget(full_button)

        self.addToolBar(toolbar)
        self._apply_shortcuts()
        return toolbar

    def _btn(self, slot, icon, tip=""):
        b = QToolButton(self)
        b.setIcon(icon); b.clicked.connect(slot); b.setAutoRaise(True)
        if tip: b.setToolTip(tip)
        return b

    def _apply_shortcuts(self):
        QShortcut(QKeySequence("Alt+Left"),  self, activated=self.go_back)
        QShortcut(QKeySequence("Alt+Right"), self, activated=self.go_forward)
        QShortcut(QKeySequence("Ctrl+R"),    self, activated=self.reload_page)
        QShortcut(QKeySequence("F11"),       self, activated=self.toggle_full_screen)
        QShortcut(QKeySequence("Ctrl+="),    self, activated=self.zoom_in)
        QShortcut(QKeySequence("Ctrl+-"),    self, activated=self.zoom_out)

    def create_menu_bar(self):
        menu_bar = QMenuBar(self)

        nav = menu_bar.addMenu("Navigation")
        for text, cb in [
            ("Back", self.go_back), ("Forward", self.go_forward),
            ("Reload", self.reload_page), ("Home", self.load_homepage),
            ("New Tab", lambda: self.create_new_tab()), ("Close Tab", lambda: self.close_tab(self.tab_widget.currentIndex())),
            ("Close Window", self.close),
        ]:
            act = QAction(text, self); act.triggered.connect(cb); nav.addAction(act)

        sec = menu_bar.addMenu("Security")
        js_act = QAction("Enable JavaScript", self, checkable=True)
        js_act.setChecked(self.javascript_enabled)
        js_act.triggered.connect(lambda: self.toggle_javascript(js_act.isChecked()))
        sec.addAction(js_act)
        sec.addSeparator()
        act_cache = QAction("Clear Cache", self); act_cache.triggered.connect(self.clear_cache); sec.addAction(act_cache)
        act_cookies = QAction("Clear Cookies", self); act_cookies.triggered.connect(self.clear_cookies); sec.addAction(act_cookies)

        hist = menu_bar.addMenu("History")
        vh = QAction("View History", self); vh.triggered.connect(self.view_history); hist.addAction(vh)
        ch = QAction("Clear History", self); ch.triggered.connect(self.clear_history); hist.addAction(ch)

        about = menu_bar.addMenu("About")
        wiki_action = QAction("Wiki", self)
        wiki_action.triggered.connect(lambda: self.create_new_tab("https://github.com/Darkelf2024/Darkelf-Browser-v3-PQC/wiki"))
        about.addAction(wiki_action)

    def custom_homepage_html(self):
        return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Darkelf Browser — Stealthy, Private, Hardened</title>
  <link rel="preconnect" href="https://cdn.jsdelivr.net" crossorigin>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css" rel="stylesheet">
  <style>
    :root{--bg:#0a0b10;--accent:#34C759;--border:rgba(255,255,255,.10);--input-bg:#12141b;--input-text:#e5e7eb;}
    *{box-sizing:border-box}
    html,body{height:100%}
    body{
      margin:0;
      font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial;
      background:
        radial-gradient(1200px 600px at 20% -10%, rgba(4,168,200,.25), transparent 60%),
        radial-gradient(1000px 600px at 120% 10%, rgba(52,199,89,.18), transparent 60%),
        var(--bg);
      color:#eef2f6;
      display:flex;
      flex-direction:column;
      justify-content:center;
      align-items:center;
    }
    .brand{
      display:flex;
      gap:10px;
      align-items:center;
      justify-content:center;
      font-weight:700;
      font-size:2rem;
    }
    .brand i{color:var(--accent);}
    .tagline{
      font-size:.95rem;
      font-weight:700;
      letter-spacing:.18em;
      text-transform:uppercase;
      color:#cfd8e3;
      margin:6px 0 20px;
    }
    .search-wrap{
      display:flex;
      align-items:stretch;
      gap:10px;
      justify-content:center;
    }
    .search-wrap input{
      height:48px;
      padding:0 16px;
      width:min(720px,92vw);
      border-radius:12px;
      border:1px solid var(--border);
      background:var(--input-bg);
      color:var(--input-text);
      font-size:16px;
      outline:none;
    }
    .search-wrap input::placeholder{color:#9aa3ad;}
    .search-wrap input:focus{
      box-shadow:0 0 0 3px rgba(52,199,89,.30);
      border-color:transparent;
    }
    .search-wrap button{
      width:48px;
      height:48px;
      border-radius:12px;
      border:none;
      cursor:pointer;
      font-size:20px;
      display:inline-flex;
      align-items:center;
      justify-content:center;
      color:#fff;
      background:var(--accent);
    }
    .search-wrap button:focus {
      outline: 2px solid #34C759;
    }
  </style>
</head>
<body>
  <div class="brand">
    <i class="bi bi-shield-lock" style="color:#34C759"></i>
    <span style="color:#34C759">Darkelf Browser</span>
  </div>
  <div class="tagline">Stealthy • Private • Hardened</div>
  <form class="search-wrap"
    action="https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/lite/"
    method="get" role="search" aria-label="Search DuckDuckGo">
    <input type="text" name="q" placeholder="Search DuckDuckGo" aria-label="Search query" />
    <button type="submit" aria-label="Search">
      <i class="bi bi-search"></i>
    </button>
  </form>
</body>
</html>
"""

    def create_new_tab(self, url="home"):
        view = QWebEngineView()
        page = SuperHardenedPage(self.web_profile, view)
        view.setPage(page)
        view.settings().setAttribute(QWebEngineSettings.JavascriptEnabled, self.javascript_enabled)
        view.loadFinished.connect(self._update_tab_title)
        view.urlChanged.connect(self.update_url_bar)
        view.setContextMenuPolicy(Qt.CustomContextMenu)
        view.customContextMenuRequested.connect(self.show_context_menu)
        if url == "home":
            view.setHtml(self.custom_homepage_html()); title = "Darkelf"
        else:
            view.setUrl(QUrl(url)); title = "New Tab"
        idx = self.tab_widget.addTab(view, title)
        self.tab_widget.setCurrentIndex(idx)
        self.tab_histories[idx] = []  # Initialize per-tab history
        return view

    def close_tab(self, index):
        if index < 0: return
        w = self.tab_widget.widget(index)
        if isinstance(w, QWebEngineView):
            try:
                p = w.page()
                if p:
                    p.setParent(None); w.setPage(None); p.deleteLater()
            except RuntimeError:
                pass
        w.close()
        self.tab_widget.removeTab(index)
        # --- Clear history for this tab ---
        if index in self.tab_histories:
            del self.tab_histories[index]
        if self.tab_widget.count() == 0:
            self.create_new_tab("home")

    def current_view(self):
        w = self.tab_widget.currentWidget()
        return w if isinstance(w, QWebEngineView) else None

    def show_context_menu(self, pos):
        v = self.current_view()
        if not v:
            return
        page = v.page()
        # Safely try to get context menu data
        data = None
        if hasattr(page, "contextMenuData"):
            try:
                data = page.contextMenuData()
            except Exception:
                data = None
        menu = QMenu(self)
        shadow = QGraphicsDropShadowEffect(menu)
        shadow.setBlurRadius(24)
        shadow.setYOffset(8)
        shadow.setColor(QColor(0, 0, 0, 160))
        menu.setGraphicsEffect(shadow)

        # KEM theme, icon size 16px
        ICON_SIZE = 16
        menu.setStyleSheet("""
            QMenu {
                background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #11161d, stop:1 #0b0f14);
                border: 1px solid #1f2937;
                border-radius: 12px;
                padding: 6px;
            }
            QMenu::separator {
                height: 1px;
                background: #1f2937;
                margin: 6px 8px;
            }
            QMenu::item {
                color: #e6f0f7;
                padding: 8px 12px;
                border-radius: 8px;
            }
            QMenu::item:selected {
                background: rgba(52,199,89,0.18);
                color: #34C759;
            }
            QMenu::icon { margin-right: 8px; }
        """)
        # Navigation
        act_back    = menu.addAction(make_text_icon('◄', ICON_SIZE), "Back",    self.go_back)
        act_forward = menu.addAction(make_text_icon('►', ICON_SIZE), "Forward", self.go_forward)
        act_reload  = menu.addAction(make_text_icon('↺', ICON_SIZE), "Reload",  self.reload_page)
        act_back.setEnabled(v.history().canGoBack())
        act_forward.setEnabled(v.history().canGoForward())
        menu.addSeparator()
        # Link actions if clicking a link
        if data and hasattr(data, "linkUrl") and data.linkUrl().isValid():
            menu.addAction(make_text_icon('⤴', ICON_SIZE), "Open Link in New Tab",
                        lambda url=data.linkUrl(): self.create_new_tab(url.toString()))
            menu.addAction("Copy Link Address",
                        lambda url=data.linkUrl():   QGuiApplication.clipboard().setText(url.toString()))
            menu.addSeparator()
        # Edit actions (use triggerAction for future compatibility)
        selected_text = getattr(data, "selectedText", lambda: "")()
        copy_action = menu.addAction("Copy", lambda: page.triggerAction(QWebEnginePage.Copy))
        copy_action.setEnabled(bool(selected_text))
        menu.addAction("Paste", lambda: page.triggerAction(QWebEnginePage.Paste))
        menu.addAction("Select All", lambda: page.triggerAction(QWebEnginePage.SelectAll))
        menu.addSeparator()
        # Zoom / View
        menu.addAction(make_text_icon('+', ICON_SIZE), "Zoom In",  self.zoom_in)
        menu.addAction(make_text_icon('−', ICON_SIZE), "Zoom Out", self.zoom_out)
        menu.addAction(make_text_icon('⛶', ICON_SIZE), "Full Screen", self.toggle_full_screen)
        menu.exec_(v.mapToGlobal(pos))
    
    def go_back(self):   v=self.current_view();  v and v.back()
    def go_forward(self):v=self.current_view();  v and v.forward()
    def reload_page(self):v=self.current_view(); v and v.reload()
    def load_homepage(self):v=self.current_view(); v and v.setHtml(self.custom_homepage_html())
    def zoom_in(self):  v=self.current_view(); v and v.setZoomFactor(v.zoomFactor()+0.1)
    def zoom_out(self): v=self.current_view(); v and v.setZoomFactor(v.zoomFactor()-0.1)

    def _update_tab_title(self):
        i = self.tab_widget.currentIndex()
        v = self.tab_widget.widget(i)
        if isinstance(v, QWebEngineView):
            self.tab_widget.setTabText(i, v.page().title())

    def update_url_bar(self, q):
        url_str = q.toString()
        if not url_str.startswith("data:text/html"):
            self.search_bar.setText(url_str)
            self.history_log.append(url_str)
            
    def search_or_load_url(self):
        text = self.search_bar.text().strip()
        if text.startswith(('http://', 'https://')):
            self.create_new_tab(text)
            return
        base = DUCK_LITE_ONION if USE_ONION_SEARCH else DUCK_LITE_HTTPS
        encoded = bytes(QUrl.toPercentEncoding(text)).decode("utf-8")
        self.create_new_tab(f"{base}{encoded}")

    def toggle_full_screen(self):
        self.setWindowState(self.windowState() ^ Qt.WindowFullScreen)

    def toggle_javascript(self, enabled):
        self.javascript_enabled = enabled
        self.settings.setValue("javascript_enabled", enabled)
        v = self.current_view()
        if v:
            v.settings().setAttribute(QWebEngineSettings.JavascriptEnabled, enabled)

    def clear_cache(self):
        self.web_profile.clearHttpCache()
        QMessageBox.information(self, "Cache Cleared", "The cache has been successfully cleared.")

    def clear_cookies(self):
        self.web_profile.cookieStore().deleteAllCookies()
        QMessageBox.information(self, "Cookies Cleared", "All cookies have been successfully cleared.")
        
    def clear_cache_and_history(self):
        profile = QWebEngineProfile.defaultProfile()
        profile.clearHttpCache()
        profile.clearAllVisitedLinks()
        self.history_log.clear()
        
    def view_history(self):
        # Show all URLs from all tabs
        urls = []
        for url_list in self.tab_histories.values():
            urls.extend(url_list)
        HistoryDialog(urls, self).exec()

    def clear_history(self):
        self.history_log.clear()
        self.web_profile.clearAllVisitedLinks()
        # Redirect every tab to homepage after history is cleared
        for i in range(self.tab_widget.count()):
            w = self.tab_widget.widget(i)
            if isinstance(w, QWebEngineView):
                w.setHtml(self.custom_homepage_html())
        QMessageBox.information(self, "Clear History", "Browsing history cleared and all tabs redirected to homepage.")

    def closeEvent(self, event):
        try:
            for i in reversed(range(self.tab_widget.count())):
                w = self.tab_widget.widget(i)
                if isinstance(w, QWebEngineView):
                    try:
                        p = w.page()
                        if p:
                            p.setParent(None); w.setPage(None); p.deleteLater()
                    except RuntimeError:
                        pass
                    w.close()
                self.tab_widget.removeTab(i)
            # stop tor on close
            self.stop_tor()
        except Exception:
            pass
        print("[exit] Darkelf closing…")
        super().closeEvent(event)

    # Optional secure delete (not used by default)
    def _secure_delete_file(self, path):
        try:
            if not os.path.exists(path): return
            size = os.path.getsize(path)
            with open(path, "r+b", buffering=0) as f:
                for _ in range(2):
                    f.seek(0); f.write(secrets.token_bytes(size)); f.flush(); os.fsync(f.fileno())
            os.remove(path)
        except Exception:
            pass

    def _secure_delete_dir(self, root):
        try:
            for r, ds, fs in os.walk(root, topdown=False):
                for name in fs:
                    self._secure_delete_file(os.path.join(r, name))
                for name in ds:
                    try: os.rmdir(os.path.join(r, name))
                    except Exception: pass
            os.rmdir(root)
        except Exception:
            pass

def main() -> int:
    app = QApplication(sys.argv)
    apply_darkelf_menu_theme()

    _defprof = QWebEngineProfile.defaultProfile()
    make_off_the_record_profile(_defprof)
    try:
        _defprof.downloadRequested.connect(lambda item: item.cancel())
    except Exception:
        pass

    w = Darkelf("home")
    w.show()
    return app.exec()
    
if __name__ == "__main__":
    main()
