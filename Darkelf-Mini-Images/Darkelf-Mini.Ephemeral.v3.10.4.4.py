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
import re
import sys
import math
import shutil
import socket
import subprocess
import tempfile
import time
import secrets
import ssl
import platform
from pathlib import Path

from PySide6.QtWebChannel import QWebChannel
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QPushButton, QLineEdit, QVBoxLayout, QMenuBar, QToolBar, QDialog, QMessageBox, QFileDialog, QProgressDialog, QListWidget, QMenu, QWidget, QLabel, QToolButton, QSizePolicy, QFrame, QHBoxLayout, QTextEdit, QGraphicsDropShadowEffect, QWidget, QPlainTextEdit
)
from PySide6.QtGui import QPalette, QColor, QKeySequence, QShortcut, QAction, QGuiApplication, QActionGroup, QIcon, QPixmap, QPainter, QFont, QCursor, QPainterPath, QKeyEvent, QTextCursor, QPen, QBrush, QLinearGradient, QPolygonF, QClipboard
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtNetwork import QNetworkProxy, QSslConfiguration, QSslSocket, QSsl, QSslCipher
from PySide6.QtWebEngineCore import (
    QWebEngineUrlRequestInterceptor, QWebEngineSettings, QWebEnginePage, QWebEngineScript, QWebEngineProfile,
    QWebEngineDownloadRequest, QWebEngineContextMenuRequest, QWebEngineCookieStore
)
from PySide6.QtCore import QUrl, QSettings, Qt, QObject, Slot, QTimer, QCoreApplication, Signal, QThread, QSize, QPoint, QByteArray, QEvent, QRectF, QPointF

# Tor + Stem
import stem.process
from stem.connection import authenticate_cookie
from stem.control import Controller
from stem import Signal as StemSignal
from stem import process as stem_process
import builtins

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
    "--site-per-process", "--disable-site-isolation-trials",
    "--disable-webrtc", "--disable-http2", "--disable-webgl", "--disable-3d-apis",
    "--disable-rtc-sctp-data-channels", "--disable-rtc-multiple-routes", "--disable-rtc-stun-origin",
    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp", "--disable-rtc-event-log", "--disable-rtc-sdp-logs",
    "--disable-webgl-2",  # keep this if you want WebGL off
    #"--disable-gpu", # Enable Flag For Windows10/11
    # REMOVED: "--disable-software-rasterizer",
    "--disable-reading-from-canvas", "--disable-offscreen-canvas",
    "--use-angle=metal",  # <- macOS uses ANGLE/Metal
    "--disable-extensions", "--disable-sync", "--disable-translate", "--disable-plugins",
    "--disable-client-side-phishing-detection", "--disable-font-subpixel-positioning", "--disable-kerning",
    "--disable-web-fonts", "--disable-background-networking", "--disable-speech-api", "--disable-sensor",
    "--disable-javascript-harmony", "--no-referrers", "--disable-renderer-backgrounding",
    "--disable-background-timer-throttling", "--disable-quic", "--disable-third-party-cookies",
    "--disable-webrtc-hw-encoding", "--disable-webrtc-hw-decoding", "--disable-webrtc-cpu-overuse-detection",
    "--disable-backgrounding-occluded-windows", "--disable-lcd-text", "--disable-accelerated-video",
    # REMOVED: "--disable-gpu-compositing",
    "--disable-text-autosizing", "--disable-peer-connection",
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
    """
    Enhanced Adblock:
    - Blocks requests to known ad/tracker domains.
    - Blocks all YouTube ad domains, player overlays, and ad scripts.
    - Whitelists main YouTube content (no blocking for www.youtube.com/watch, img, video, etc).
    """
    def __init__(self, parent=None, ad_domains=None):
        super().__init__(parent)
        # Default ad/tracker domains. Add more as needed!
        self.ad_domains = set(ad_domains or [
            # --- Global ad/tracker domains ---
            "doubleclick.net", "googlesyndication.com", "adsafeprotected.com", "adservice.google.com",
            "adnxs.com", "yieldmanager.com", "scorecardresearch.com", "quantserve.com",
            "securepubads.g.doubleclick.net", "pagead2.googlesyndication.com",
            "partner.googleadservices.com", "adform.net", "adroll.com", "taboola.com",
            "outbrain.com", "criteo.com", "googletagmanager.com", "analytics.google.com",
            "advertising.com", "media.net", "bing.com", "yahoo.com", "zedo.com",
            "pubmatic.com", "openx.net", "rubiconproject.com", "moatads.com",
            "mathtag.com", "bluekai.com",
            # --- YouTube ad-specific domains ---
            "youtube.com/api/stats/ads", "youtube.com/pagead", "youtube.com/get_midroll_info",
            "youtube.com/ptracking", "youtube.com/youtubei/v1/ads", "youtube.com/youtubei/v1/player/ad_break",
            "youtube.com/ad_break", "youtube.com/ad_video", "youtube.com/api/ad", "youtube.com/s/ads",
            "googleads.g.doubleclick.net", "yt3.ggpht.com",
            "youtube.com/yva_video", "youtube.com/yva_ads", "youtube.com/api/stats/ads",
            "youtube.com/ads", "youtube.com/get_ads", "youtube.com/api/ads"
        ])
        # YouTube main content whitelist (do NOT block these)
        self.youtube_whitelist = [
            "www.youtube.com/", "m.youtube.com/", "youtube.com/embed/", "youtube.com/watch",
            "youtube.com/shorts", "youtube.com/live", "youtube.com/results", "youtube.com/channel",
            "youtube.com/user", "youtube.com/playlist", "youtube.com/feed", "youtube.com/c/",
            "youtube.com/img", "youtube.com/s/player/", "youtube.com/s/desktop_player/", "youtube.com/s/player-desktop/",
        ]

    def interceptRequest(self, info):  # type: ignore[override]
        try:
            url = info.requestUrl().toString().lower()
            # --- Whitelist YouTube main content ---
            if any(url.startswith(wl) for wl in self.youtube_whitelist):
                info.block(False)
                return

            # --- Block YouTube ad/tracker URLs ---
            if "youtube.com" in url:
                # Block known ad endpoints, overlay scripts, and ad APIs
                if any(ad in url for ad in [
                    "/api/stats/ads", "/pagead", "/get_midroll_info", "/ptracking",
                    "/v1/ads", "/ad_break", "/ad_video", "/api/ad", "/s/ads", "/ads",
                    "/get_ads", "/api/ads", "googleads.g.doubleclick.net"
                ]):
                    info.block(True)
                    return
                # Block s.ytimg.com/ad scripts and overlays
                if "s.ytimg.com" in url and "/ad" in url:
                    info.block(True)
                    return
                # Block yt3.ggpht.com (ad avatars/images)
                if "yt3.ggpht.com" in url:
                    info.block(True)
                    return

            # --- Block global ad/tracker domains ---
            if any(domain in url for domain in self.ad_domains):
                info.block(True)
                return
            # Otherwise, allow
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
            
class IPLeakGuard(QWebEngineUrlRequestInterceptor):
    """
    Blocks all requests to localhost and private IP ranges to prevent deanonymization/leaks.
    """
    def interceptRequest(self, info):
        url = info.requestUrl().toString().lower()
        # Block localhost and RFC1918 private ranges
        if re.search(
            r'127\.0\.0\.1|localhost|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.',
            url
        ):
            info.block(True)
            print("[IPLeakGuard] Blocked: " + url)
            return
        # Block file and ftp schemes
        if url.startswith("file:") or url.startswith("ftp:"):
            info.block(True)
            print("[IPLeakGuard] Blocked protocol: " + url)
            return
            
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
        const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0";
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
        
class CanvasProtectionMixin:
    def inject_canvas_protection(self):
        script = r"""
        (() => {
          // ---- Idempotence guard -------------------------------------------------
          const kGuard = "__darkelf_canvas_protection_installed__";
          if (self[kGuard]) return;
          self[kGuard] = true;

          // ---- Mode switch -------------------------------------------------------
          // "tor_mimic" -> stable, low-amplitude noise on readout, WebGL disabled
          // "max_blank" -> return blanks for all readouts, WebGL disabled
          const MODE = "tor_mimic";  // change to "max_blank" for your other mode

          // ---- Stable PRNG per (origin + sessionSecret) -------------------------
          const secret = crypto.getRandomValues(new Uint32Array(2));
          function mulberry32(a){return function(){let t=a+=0x6D2B79F5;t=Math.imul(t^t>>>15,t|1);t^=t+Math.imul(t^t>>>7,t|61);return ((t^t>>>14)>>>0)/4294967296}}
          const seed = (new TextEncoder().encode(location.host + "|" + secret.join(","))).reduce((a,b)=>(a*131+b)>>>0,0)>>>0;
          const rand = mulberry32(seed);
          const n8 = () => (rand()*10 - 5)|0;  // [-5,+5]

          // ---- Helpers -----------------------------------------------------------
          const nativeSig = fn => { try { Object.defineProperty(fn, "toString", { value: () => `function ${fn.name||""}() { [native code] }` }); } catch(_){} };
          const cloneImageData = (id) => {
            try {
              const out = new ImageData(id.width, id.height);
              out.data.set(id.data);
              return out;
            } catch {
              // Fallback for older engines
              const out = { data: new Uint8ClampedArray(id.data), width: id.width, height: id.height };
              return out;
            }
          };

          const noiseImageData = (id) => {
            if (MODE === "max_blank") {
              id.data.fill(0);
              return id;
            }
            // tor_mimic: low amplitude noise, do not change alpha
            for (let i=0;i<id.data.length;i+=4){
              id.data[i]   = Math.max(0,Math.min(255,id.data[i]   + n8()));
              id.data[i+1] = Math.max(0,Math.min(255,id.data[i+1] + n8()));
              id.data[i+2] = Math.max(0,Math.min(255,id.data[i+2] + n8()));
            }
            return id;
          };

          const readoutWithNoise = (canvas, mime, quality, asBlob, cb) => {
            try {
              const w = canvas.width, h = canvas.height;
              const ctx = canvas.getContext("2d");
              if (!ctx || !w || !h) {
                if (asBlob) return cb && cb(null);
                return "data:,";
              }

              // Read original pixels from the real canvas
              const orig = ctx.getImageData(0, 0, w, h);
              // Clone and add noise (do NOT mutate the real canvas)
              const noisy = noiseImageData(cloneImageData(orig));

              // Paint noisy pixels onto a temporary offscreen canvas
              const tmp = document.createElement("canvas");
              tmp.width = w; tmp.height = h;
              const tctx = tmp.getContext("2d");
              tctx.putImageData(noisy, 0, 0);

              if (asBlob) {
                // toBlob path
                try {
                  tmp.toBlob(cb, mime, quality);
                } catch {
                  // Fallback: convert dataURL to Blob
                  const dataURL = tmp.toDataURL(mime, quality);
                  const arr = dataURL.split(','), bstr = atob(arr[1]||"");
                  const u8 = new Uint8Array(bstr.length);
                  for (let i=0;i<bstr.length;i++) u8[i] = bstr.charCodeAt(i);
                  cb && cb(new Blob([u8], { type: (arr[0].split(':')[1]||"image/png").split(';')[0] }));
                }
                return;
              } else {
                // toDataURL path
                return tmp.toDataURL(mime, quality);
              }
            } catch (e) {
              // Last-resort fallback
              if (asBlob) return cb && cb(null);
              return "data:,";
            }
          };

          // ---- Patch Canvas 2D readouts -----------------------------------------
          const O_C2D_getImageData = CanvasRenderingContext2D.prototype.getImageData;
          CanvasRenderingContext2D.prototype.getImageData = function(x,y,w,h){
            const id = O_C2D_getImageData.apply(this, arguments);
            // Return noisy clone; do NOT change backing store
            return noiseImageData(cloneImageData(id));
          };
          nativeSig(CanvasRenderingContext2D.prototype.getImageData);

          const O_CANVAS_toDataURL = HTMLCanvasElement.prototype.toDataURL;
          HTMLCanvasElement.prototype.toDataURL = function(mime, quality){
            // Return noisy export; keep original pixels intact
            return readoutWithNoise(this, mime, quality, false);
          };
          nativeSig(HTMLCanvasElement.prototype.toDataURL);

          const O_CANVAS_toBlob = HTMLCanvasElement.prototype.toBlob;
          HTMLCanvasElement.prototype.toBlob = function(cb, mime, quality){
            return readoutWithNoise(this, mime, quality, true, cb);
          };
          nativeSig(HTMLCanvasElement.prototype.toBlob);

          // ---- OffscreenCanvas coverage -----------------------------------------
          if (typeof OffscreenCanvas !== "undefined") {
            try {
              const O_OSC_convertToBlob = OffscreenCanvas.prototype.convertToBlob;
              OffscreenCanvas.prototype.convertToBlob = async function(opts){
                const ctx = this.getContext("2d");
                if (!ctx) return O_OSC_convertToBlob ? O_OSC_convertToBlob.call(this, opts) : new Blob();
                const id = ctx.getImageData(0,0,this.width,this.height);
                const noisy = noiseImageData(cloneImageData(id));

                // draw noisy data into a temp onscreen canvas to re-encode
                const tmp = document.createElement("canvas");
                tmp.width = this.width; tmp.height = this.height;
                tmp.getContext("2d").putImageData(noisy,0,0);
                return new Promise(res => tmp.toBlob(res, (opts && opts.type) || "image/png", (opts && opts.quality)));
              };
              nativeSig(OffscreenCanvas.prototype.convertToBlob);
            } catch(_) {}

            try {
              const O_OSC_toDataURL = OffscreenCanvas.prototype.toDataURL;
              if (O_OSC_toDataURL) {
                OffscreenCanvas.prototype.toDataURL = function(type, quality){
                  // emulate via convertToBlob for noisy path
                  // (Some engines don’t implement toDataURL; safe to skip)
                  return O_OSC_toDataURL.call(this, type, quality);
                };
                nativeSig(OffscreenCanvas.prototype.toDataURL);
              }
            } catch(_) {}
          }

          // ---- WebGL disabling (Tor-mimic) --------------------------------------
          const O_CANVAS_getContext = HTMLCanvasElement.prototype.getContext;
          HTMLCanvasElement.prototype.getContext = function(type, attrs){
            if (type === "webgl" || type === "webgl2") return null;
            return O_CANVAS_getContext.call(this, type, attrs);
          };
          nativeSig(HTMLCanvasElement.prototype.getContext);

          // ---- Also disable WebGL constructors to reduce side channels ----------
          try { Object.defineProperty(window, "WebGLRenderingContext", { value: undefined }); } catch(_){}
          try { Object.defineProperty(window, "WebGL2RenderingContext", { value: undefined }); } catch(_){}
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation, subframes=True)

class DarkelfHardenedProfile:
    """
    Helper to install JS and interceptor to fully block sec-ch-ua leaks
    and neutralize iframes, matching KEM768-level privacy.
    """
    @staticmethod
    def install(profile, remove_iframes=True):
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
                        Object.defineProperty(w.navigator, "userAgent", { get: () => "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0", configurable: true });
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

class YoutubeMixin:
    """
    YoutubeMixin:
    - Applies all YouTube compatibility/fingerprinting shields only for *.youtube.com.
    - Applies canvas randomization, WebGL spoofing, font spoofing, WebRTC block, language/timezone spoofing.
    - Blocks cookies, disables local storage, disables plugins.
    - Hooks mitmproxy adblocker (if present).
    - Drop-in: call YoutubeMixin().apply_to_page(page, adblocker) after navigation if 'youtube.com' in URL.
    """

    def __init__(self, adblocker=None):
        self.adblocker = adblocker

    def apply_to_page(self, page, url=None):
        if not url:
            try:
                url = page.url().toString()
            except Exception:
                url = ""
        if not self.is_youtube(url):
            return

        # --- YouTube compatibility/fingerprint shields ---
        self.patch_youtube_compatibility(page)
        self.spoof_canvas(page)
        self.spoof_webgl(page)
        self.spoof_fonts(page)
        self.block_cookies_and_storage(page)
        self.block_plugins_and_webrtc(page)
        self.spoof_language_timezone(page)

        # --- Adblock hook (mitmproxy) ---
        if self.adblocker and hasattr(self.adblocker, "hook_to_page"):
            try:
                self.adblocker.hook_to_page(page)
            except Exception as e:
                print(f"[YoutubeMixin] Adblocker hook error: {e}")

    def is_youtube(self, url):
        if not url: return False
        return ".youtube.com" in url or "youtube.com" in url or "ytimg.com" in url

    def patch_youtube_compatibility(self, page):
        # Already in your inject_all_scripts, but here as a separate patch for mixin
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
        self.inject_script(page, script)

    def spoof_canvas(self, page):
        # Add pixel randomization for canvas fingerprinting
        script = """
        (() => {
            const origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
            CanvasRenderingContext2D.prototype.getImageData = function(x, y, w, h) {
                const imgData = origGetImageData.apply(this, arguments);
                for (let i = 0; i < imgData.data.length; i += 4) {
                    imgData.data[i]     = Math.max(0, Math.min(255, imgData.data[i] + Math.floor(Math.random() * 10) - 5));
                    imgData.data[i + 1] = Math.max(0, Math.min(255, imgData.data[i + 1] + Math.floor(Math.random() * 10) - 5));
                    imgData.data[i + 2] = Math.max(0, Math.min(255, imgData.data[i + 2] + Math.floor(Math.random() * 10) - 5));
                }
                return imgData;
            };
            const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
            HTMLCanvasElement.prototype.toDataURL = function() {
                const ctx = this.getContext("2d");
                if (ctx) {
                    const w = this.width, h = this.height;
                    const imgData = ctx.getImageData(0, 0, w, h);
                    for (let i = 0; i < imgData.data.length; i += 4) {
                        imgData.data[i]     = Math.max(0, Math.min(255, imgData.data[i] + Math.floor(Math.random() * 10) - 5));
                        imgData.data[i + 1] = Math.max(0, Math.min(255, imgData.data[i + 1] + Math.floor(Math.random() * 10) - 5));
                        imgData.data[i + 2] = Math.max(0, Math.min(255, imgData.data[i + 2] + Math.floor(Math.random() * 10) - 5));
                    }
                    ctx.putImageData(imgData, 0, 0);
                    return origToDataURL.apply(this, arguments);
                }
                return origToDataURL.apply(this, arguments);
            };
        })();
        """
        self.inject_script(page, script)

    def spoof_webgl(self, page):
        script = """
        (() => {
            const spoofedVendor = "Google Inc.";
            const spoofedRenderer = "ANGLE (Intel, Intel Iris Xe Graphics, Direct3D11 vs_5_0 ps_5_0)";

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
        })();
        """
        self.inject_script(page, script)

    def spoof_fonts(self, page):
        script = """
        (() => {
            const randomize = (val, factor = 0.03) => val + (Math.random() * val * factor);
            const originalMeasureText = CanvasRenderingContext2D.prototype.measureText;
            CanvasRenderingContext2D.prototype.measureText = function(text) {
                const metrics = originalMeasureText.call(this, text);
                metrics.width = randomize(metrics.width);
                return metrics;
            };
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
        })();
        """
        self.inject_script(page, script)

    def block_cookies_and_storage(self, page):
        script = """
        (() => {
            Object.defineProperty(document, 'cookie', {
                get: () => "",
                set: () => {},
                configurable: true
            });
            Object.defineProperty(window, 'localStorage', { value: null, writable: false });
            Object.defineProperty(window, 'sessionStorage', { value: null, writable: false });
            Object.defineProperty(window, 'indexedDB', { value: null, writable: false });
        })();
        """
        self.inject_script(page, script)

    def block_plugins_and_webrtc(self, page):
        script = """
        (() => {
            Object.defineProperty(navigator, 'plugins', {
                get: () => [],
                configurable: true
            });
            Object.defineProperty(navigator, 'mimeTypes', {
                get: () => [],
                configurable: true
            });
            Object.defineProperty(window, 'RTCPeerConnection', { value: undefined, configurable: false });
            Object.defineProperty(window, 'webkitRTCPeerConnection', { value: undefined, configurable: false });
        })();
        """
        self.inject_script(page, script)

    def spoof_language_timezone(self, page):
        script = """
        (() => {
            Object.defineProperty(navigator, 'language', {
                get: () => 'en-US',
                configurable: true
            });
            Object.defineProperty(navigator, 'languages', {
                get: () => ['en-US', 'en'],
                configurable: true
            });
            Object.defineProperty(Intl.DateTimeFormat.prototype, 'resolvedOptions', {
                value: function() {
                    return { timeZone: "UTC", locale: "en-US" };
                },
                configurable: true
            });
        })();
        """
        self.inject_script(page, script)

    def inject_script(self, page, script_str):
        script = QWebEngineScript()
        script.setSourceCode(script_str)
        script.setInjectionPoint(QWebEngineScript.DocumentCreation)
        script.setWorldId(QWebEngineScript.MainWorld)
        script.setRunsOnSubFrames(False)
        page.profile().scripts().insert(script)
        
class DarkelfCompatSandbox:
    """
    Darkelf-Compatible Sandbox:
    - Auto-detects .onion vs clearnet.
    - For .onion: Applies most shields, skips font spoofing.
    - For clearnet: Applies strict sandbox, disables disk and persistent features.
    - For fingerprinting/test sites: Applies all shields, extra spoofing.
    - Adblocker can be hooked (from mitmproxy) as needed.
    - Drop-in for SuperHardenedPage (call .sandbox_for_url(url, page) on navigation).
    """

    TEST_SITES = [
        "coveryourtracks.eff.org",
        "browserleaks.com",
        "amiunique.org",
        "fingerprint.com",
        "pixelscan.net",
        "creepjs",
        "fpcentral",
    ]

    def __init__(self, adblocker=None):
        # adblocker: should be a class with a method hook_to_page(page)
        self.adblocker = adblocker

    def is_onion(self, url):
        return ".onion" in url if url else False

    def is_test_site(self, url):
        if not url:
            return False
        host = re.sub(r'^https?://', '', url).split('/')[0].lower()
        return any(site in host for site in self.TEST_SITES)

    def sandbox_for_url(self, url, page):
        """
        Main entry point: call this in your SuperHardenedPage or QWebEnginePage after navigation.
        Applies sandbox and injects scripts. 
        DO NOT call page.inject_all_scripts() here (avoid recursion).
        """
        # .onion: Optionally skip font spoofing, but don't re-inject all scripts
        if self.is_onion(url):
            # Optionally: Remove font spoofing after all shields
            # page.disable_font_spoofing() if you implement that
            pass
        elif self.is_test_site(url):
            # Fingerprinting test site: inject extra spoofing
            self.inject_extra_spoofing(page)
        else:
            # Clearnet: strict sandbox only
            self.apply_strict_sandbox(page)
        
        # Hook mitmproxy adblocker if present
        if self.adblocker and hasattr(self.adblocker, "hook_to_page"):
            try:
                self.adblocker.hook_to_page(page)
            except Exception as e:
                print(f"[DarkelfCompatSandbox] Adblocker hook error: {e}")

    def inject_compat_scripts(self, page, url):
        self.sandbox_for_url(url, page)

    def apply_strict_sandbox(self, page):
        """
        Applies strict sandbox for clearnet: disables all local persistence, advanced APIs.
        """
        script = """
        (() => {
            Object.defineProperty(window, 'localStorage', { value: null, writable: false });
            Object.defineProperty(window, 'sessionStorage', { value: null, writable: false });
            Object.defineProperty(window, 'indexedDB', { value: null, writable: false });
            Object.defineProperty(document, 'cookie', { get: () => "", set: () => {}, configurable: true });
            Object.defineProperty(window, 'BroadcastChannel', { value: null, writable: false });
            Object.defineProperty(window, 'SharedWorker', { value: null, writable: false });
            Object.defineProperty(window, 'ServiceWorker', { value: null, writable: false });
            Object.defineProperty(window, 'caches', { value: null, writable: false });

            // Disable downloads
            if (navigator && navigator.downloads) {
                navigator.downloads = undefined;
            }

            // Disable file access
            window.File = undefined;
            window.FileReader = undefined;
            window.Blob = undefined;

            // Disable popups/clipboard
            window.open = function() { return null; };
            document.execCommand = function() { return false; };

            // Disable plugins, WebRTC, WebGL, WebBluetooth, WebGPU, MediaDevices, etc.
            Object.defineProperty(navigator, 'plugins', { value: [], configurable: true });
            Object.defineProperty(navigator, 'mimeTypes', { value: [], configurable: true });
            Object.defineProperty(window, 'RTCPeerConnection', { value: undefined, configurable: false });
            Object.defineProperty(window, 'WebGLRenderingContext', { value: undefined, configurable: false });
            Object.defineProperty(navigator, 'bluetooth', { get: () => undefined });
            Object.defineProperty(navigator, 'gpu', { get: () => undefined });
            Object.defineProperty(navigator, 'mediaDevices', { get: () => undefined });

            // Disable eval and WebSocket
            window.eval = function() { return undefined; };
            window.WebSocket = function() { return { send() {}, close() {}, readyState: 3 }; };

            // Disable geolocation, notifications, sensors, background sync, speech, battery, pointer, device memory, hardware concurrency, CSP bypass, FontFaceSet, permissions API, window.chrome, idle detector, audio context, supercookies, tracking requests, cookie banners, fingerprint vectors
            Object.defineProperty(navigator, "geolocation", { get: () => undefined });
            Object.defineProperty(navigator, "permissions", { get: () => undefined });
            Object.defineProperty(window, "chrome", { value: undefined, configurable: true });
            Object.defineProperty(Intl.DateTimeFormat.prototype, 'resolvedOptions', { value: () => ({ timeZone: "UTC", locale: "en-US" })});
            Object.defineProperty(document, "fonts", { value: { ready: Promise.resolve(), check: () => false, load: () => Promise.reject("Blocked"), values: () => [], size: 0 } });
            Object.defineProperty(window, "IdleDetector", { value: undefined });
            Object.defineProperty(window, "AudioContext", { value: undefined });
            Object.defineProperty(window, "webkitAudioContext", { value: undefined });
            Object.defineProperty(window, "openDatabase", { value: null });
            Object.defineProperty(window, "localStorage", { value: null });
            Object.defineProperty(window, "sessionStorage", { value: null });
            Object.defineProperty(window, "indexedDB", { value: null });
            Object.defineProperty(document, "cookie", { get: () => "", set: () => {}, configurable: false });

            Object.defineProperty(navigator, "maxTouchPoints", { get: () => 0 });
            Object.defineProperty(navigator, "deviceMemory", { get: () => 4 });
            Object.defineProperty(navigator, "hardwareConcurrency", { get: () => 4 });

            var meta = document.createElement('meta');
            meta.httpEquiv = "Content-Security-Policy";
            meta.content = "default-src 'none'; script-src 'self' 'unsafe-inline' https:; connect-src 'self' https: wss:; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'; font-src 'self' https:; media-src 'none'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; upgrade-insecure-requests; block-all-mixed-content;";
            document.head.appendChild(meta);
        })();
        """
        page.inject_script(script, injection_point=QWebEngineScript.DocumentCreation, subframes=True)

    def inject_extra_spoofing(self, page):
        """
        For test/fingerprint sites: inject extra UA/letterbox/canvas/font spoofing.
        """
        ua_script = """
        (() => {
            Object.defineProperty(navigator, 'userAgent', { get: () => "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0" });
            Object.defineProperty(navigator, 'platform', { get: () => "Win32" });
            Object.defineProperty(navigator, 'languages', { get: () => ["en-US","en"] });
            Object.defineProperty(navigator, 'language', { get: () => "en-US" });
            Object.defineProperty(window, 'innerWidth', { get: () => 1000 });
            Object.defineProperty(window, 'innerHeight', { get: () => 1000 });
            Object.defineProperty(window, 'outerWidth', { get: () => 1000 });
            Object.defineProperty(window, 'outerHeight', { get: () => 1000 });
            Object.defineProperty(screen, 'width', { get: () => 1000 });
            Object.defineProperty(screen, 'height', { get: () => 1000 });
            Object.defineProperty(screen, 'availWidth', { get: () => 1000 });
            Object.defineProperty(screen, 'availHeight', { get: () => 980 });
            Object.defineProperty(screen, 'colorDepth', { get: () => 24 });
        })();
        """
        page.inject_script(ua_script, injection_point=QWebEngineScript.DocumentCreation, subframes=True)
        canvas_script = """
        (() => {
            const origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
            CanvasRenderingContext2D.prototype.getImageData = function(x, y, w, h) {
                const imgData = origGetImageData.apply(this, arguments);
                for (let i = 0; i < imgData.data.length; i += 4) {
                    imgData.data[i]     = Math.max(0, Math.min(255, imgData.data[i] + Math.floor(Math.random() * 10) - 5));
                    imgData.data[i + 1] = Math.max(0, Math.min(255, imgData.data[i + 1] + Math.floor(Math.random() * 10) - 5));
                    imgData.data[i + 2] = Math.max(0, Math.min(255, imgData.data[i + 2] + Math.floor(Math.random() * 10) - 5));
                }
                return imgData;
            };
            const origMeasureText = CanvasRenderingContext2D.prototype.measureText;
            CanvasRenderingContext2D.prototype.measureText = function(text) {
                const metrics = origMeasureText.call(this, text);
                metrics.width += Math.random();
                return metrics;
            };
        })();
        """
        page.inject_script(canvas_script, injection_point=QWebEngineScript.DocumentCreation, subframes=True)
        
class SuperHardenedPage(QWebEnginePage, _UAChNavigatorHardMixin, _DarkelfLetterboxMixin, CanvasProtectionMixin):
    def __init__(self, profile, parent=None, adblocker=None):
        super().__init__(profile, parent)
        self.profile = profile
        self.setParent(parent)
        self.view = parent
        self.compat_sandbox = DarkelfCompatSandbox(adblocker=adblocker)
        self.featurePermissionRequested.connect(self.onFeatureRequested)
        self.inject_all_scripts()
        
    def createWindow(self, _type):  # popup blocker
        # Block new window / tab requests (target=_blank, window.open)
        return None
        
    def certificateError(self, error):  # type: ignore[override]
        return False
        
    def block_webassembly(self):
        script = "window.WebAssembly = undefined;"
        self.inject_script(script, QWebEngineScript.DocumentCreation, subframes=True)
        
    def block_misc_apis(self):
        script = """
        window.PaymentRequest = undefined;
        window.Gamepad = undefined;
        window.Magnetometer = undefined;
        window.AmbientLightSensor = undefined;
        window.ProximitySensor = undefined;
        window.Serial = undefined;
        window.HID = undefined;
        """
        self.inject_script(script, QWebEngineScript.DocumentCreation, subframes=True)
        
    def acceptNavigationRequest(self, url, _type, isMainFrame):
        # Warn user if leaving .onion (Tor) to clearnet
        if isMainFrame:
            try:
                from_host = self.url().host() if self.url().isValid() else ""
                to_host = url.host()
                if from_host.endswith(".onion") and not to_host.endswith(".onion") and to_host:
                    QMessageBox.warning(
                        None, "Privacy Warning",
                        "You are leaving a .onion (Tor) site for the clearnet."
                    )
            except Exception:
                pass  # Always fail safe

        # Block javascript: navigation
        if url.scheme() == "javascript":
            return False

        # Block file:// navigation for extra safety
        if url.scheme() == "file":
            return False

        # Allow data: URLs only for homepage and subframes
        if url.scheme() == "data":
            if isMainFrame and "Darkelf Browser" in url.toString():
                return True
            if not isMainFrame:
                return True
            return False

        return super().acceptNavigationRequest(url, _type, isMainFrame)

    def onFeatureRequested(self, origin, feature):
        self.setFeaturePermission(origin, feature, QWebEnginePage.PermissionPolicy.DeniedByUser)

    def inject_script(self, script_str, injection_point=QWebEngineScript.DocumentReady, subframes=True):
        script = QWebEngineScript()
        script.setSourceCode(script_str)
        script.setInjectionPoint(injection_point)
        script.setWorldId(QWebEngineScript.MainWorld)
        script.setRunsOnSubFrames(subframes)
        self.profile.scripts().insert(script)

    @staticmethod
    def setup_ssl_configuration():
        """Prefer TLS 1.3 if available; safe static helper for SSL setup."""
        try:
            from PySide6.QtNetwork import QSslConfiguration, QSsl
        except Exception:
            return
        try:
            cfg = QSslConfiguration.defaultConfiguration()
            # Pick the strongest protocol supported by this Qt build
            for proto in ("TlsV1_3", "TlsV1_3OrLater", "TlsV1_2OrLater"):
                if hasattr(QSsl, proto):
                    cfg.setProtocol(getattr(QSsl, proto))
                    break
            QSslConfiguration.setDefaultConfiguration(cfg)
        except Exception:
            pass
            
    def inject_all_scripts(self):
        self.inject_uach_off_everywhere()
        self.inject_darkelf_letterboxing()
        self.inject_click_to_play_media()
        self.block_webassembly()
        self.block_misc_apis()
        self.inject_canvas_protection()
        self.inject_navigator_darkelf_baseline()
        self.inject_timing_quantization()
        self.inject_block_blob_file_fetch()
        self.inject_geolocation_override()
        self.inject_useragentdata_kill()
        self.inject_navigator_prototype_spoof()
        self.enable_user_select_script()
        self.enable_scrolling_script()
        self.inject_capslock_fix()
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

        url = ""
        if self.view and hasattr(self.view, "url"):
            try:
                url = self.view.url().toString()
            except Exception:
                url = ""
        # Prefer this call for future use:
        self.compat_sandbox.sandbox_for_url(url, self)
        
    def inject_navigator_darkelf_baseline(self):
        script = r"""
        (() => {
          // Tor Browser ESR (Windows) lookalikes
          const defs = {
            userAgent: "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0",
            platform: "Win32",
            vendor: "",
            language: "en-US",
            languages: Object.freeze(["en-US","en"]),
            webdriver: false,
            doNotTrack: "1",
            maxTouchPoints: 0,
            // Tor keeps these low/undefined
            hardwareConcurrency: 2,
            deviceMemory: undefined
          };

          for (const [k,v] of Object.entries(defs)){
            try { Object.defineProperty(Navigator.prototype, k, { get: ()=>v, configurable: true }); } catch(_){}
            try { Object.defineProperty(navigator, k, { get: ()=>v, configurable: true }); } catch(_){}
          }

          // Kill UA-CH
          try { Object.defineProperty(Navigator.prototype, "userAgentData", { get: ()=>undefined, configurable: true }); } catch(_){}
          try { Object.defineProperty(navigator, "userAgentData", { get: ()=>undefined, configurable: true }); } catch(_){}
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation, subframes=True)

    def inject_timing_quantization(self):
        script = r"""
        (() => {
          const base = 10; // ms buckets
          // Stable per-origin jitter in [0, base)
          const host = location.host;
          let h = 2166136261;
          for (let i=0;i<host.length;i++) {
            h ^= host.charCodeAt(i);
            h = Math.imul(h, 16777619);
          }
          const jitter = (h >>> 0) % base;

          const q = (t) => Math.floor(t / base) * base + jitter;

          const oNow = performance.now.bind(performance);
          performance.now = () => q(oNow());

          const oDateNow = Date.now.bind(Date);
          Date.now = () => q(oDateNow());
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation, subframes=True)

    def inject_audio_noise(self):
        script = r"""
        (() => {
          // Per-origin pseudo-random but stable
          const host = location.host;
          let s = 0;
          for (let i = 0; i < host.length; i++) {
            s = (s * 131 + host.charCodeAt(i)) >>> 0;
          }
          function prng() {
            s = (s * 1664525 + 1013904223) >>> 0;
            return (s >>> 8) / 16777216;
          }

          const oGet = AudioBuffer.prototype.getChannelData;
          Object.defineProperty(AudioBuffer.prototype, 'getChannelData', {
            value: function(ch) {
              const data = oGet.call(this, ch);
              const out = new Float32Array(data.length);
              for (let i = 0; i < data.length; i++) {
                // small, zero-mean noise
                out[i] = Math.max(-1, Math.min(1, data[i] + (prng() - 0.5) * 0.002));
              }
              return out;
            }
          });

          try {
            Object.defineProperty(AudioBuffer.prototype.getChannelData, 'toString', {
              value: () => `function getChannelData() { [native code] }`
            });
          } catch(_) {}
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation, subframes=True)
        
    def inject_click_to_play_media(self):
        script = """
        (() => {
            // Patch play() so it only works after user gesture
            const origPlay = HTMLMediaElement.prototype.play;
            HTMLMediaElement.prototype.play = function() {
                if (!this._userInitiated) {
                    this.muted = true;
                    this.pause();
                    // Optionally, show a custom overlay here
                    return Promise.reject('User gesture required');
                }
                return origPlay.apply(this, arguments);
            };
            // Allow play after any user click/tap
            document.addEventListener('click', () => {
                document.querySelectorAll('video, audio').forEach(m => m._userInitiated = true);
            }, true);
            // Make autoplay detection APIs always say "allowed"
            Object.defineProperty(document, "autoplayPolicy", {
                get: () => "allowed",
                configurable: true
            });
            HTMLMediaElement.prototype.autoplay = true;
            // Spoof canAutoplay fingerprinting
            window.canAutoplay = { video: () => Promise.resolve(true), audio: () => Promise.resolve(true) };
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation, subframes=True)
        
    def inject_block_blob_file_fetch(self):
        script = """
        (() => {
            const origFetch = window.fetch;
            window.fetch = function(resource, ...args) {
                let url = resource;
                if (typeof url !== 'string' && url && url.url) url = url.url;
                if (typeof url === 'string' && (url.startsWith('blob:') || url.startsWith('file:'))) {
                    throw new Error('Blocked fetch to blob: or file: URL for security.');
                }
                return origFetch.apply(this, arguments);
            };
            const origOpen = XMLHttpRequest.prototype.open;
            XMLHttpRequest.prototype.open = function(method, url, ...args) {
                if (typeof url === 'string' && (url.startsWith('blob:') || url.startsWith('file:'))) {
                    throw new Error('Blocked XHR to blob: or file: URL for security.');
                }
                return origOpen.apply(this, arguments);
            };
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation, subframes=True)
    
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
        
    def inject_capslock_fix(self):
        script = r"""
        (function() {
            if (!navigator.platform.toLowerCase().includes('mac')) return;
            let lastCapsToggle = 0, capsOn = false;
            document.addEventListener('keydown', function(ev) {
                if (ev.key === "CapsLock") {
                    capsOn = !capsOn;
                    lastCapsToggle = Date.now();
                }
            });
            function fixInput(e) {
                let input = e.target;
                if (!input || !input.tagName) return;
                if (
                    (input.tagName === "INPUT" && input.type === "text") ||
                    input.tagName === "TEXTAREA" ||
                    input.isContentEditable
                ) {
                    let val = (input.value !== undefined ? input.value : input.innerText);
                    if (!val) return;
                    let now = Date.now();
                    if (now - lastCapsToggle < 500 && capsOn) {
                        let last = val[val.length - 1];
                        if (last && last >= "a" && last <= "z") {
                            if (input.value !== undefined) {
                                input.value = val.slice(0, -1) + last.toUpperCase();
                                input.setSelectionRange(input.value.length, input.value.length);
                            } else {
                                input.innerText = val.slice(0, -1) + last.toUpperCase();
                                let sel = window.getSelection();
                                if (sel && input.lastChild) sel.collapse(input.lastChild, input.lastChild.length);
                            }
                        }
                    }
                }
            }
            document.addEventListener('input', fixInput, true);
        })();
        """
        self.inject_script(script, QWebEngineScript.DocumentCreation, subframes=True)
        
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
        # final surface values (Firefox 128 on Win32; vendor empty)
        script = r"""
        (() => {
          const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0";

          const defs = {
            userAgent: UA,
            appVersion: "5.0 (Windows NT 10.0)",
            platform: "Win32",
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

    def inject_stealth_profile(self):
        script = """
        (() => {
            const spoofUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0";

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
                'div[class*="optin"]',
                'div[data-cookie]',
                'div[data-privacy]',
                'footer', // Some banners are in footers
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

            function removeBanners(root = document) {
                let found = false;
                for (const sel of selectors) {
                    root.querySelectorAll(sel).forEach(el => {
                        if (isCookieBanner(el)) {
                            removeElement(el);
                            found = true;
                        }
                    });
                }
                // Try generic banners
                root.querySelectorAll("div,section").forEach(el => {
                    if (el.offsetHeight > 30 && isCookieBanner(el)) {
                        removeElement(el);
                        found = true;
                    }
                });
                return found;
            }

            function scanShadowDOM(root) {
                try {
                    const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT, null, false);
                    while (walker.nextNode()) {
                        const node = walker.currentNode;
                        if (node.shadowRoot) {
                            removeBanners(node.shadowRoot);
                            scanShadowDOM(node.shadowRoot);
                        }
                    }
                } catch (_) {}
            }

            function harden() {
                removeBanners(document);
                scanShadowDOM(document);
                // Hide possible overlays
                document.body.style.setProperty("overflow", "auto", "important");
                document.body.style.setProperty("position", "static", "important");
            }

            // Run several times to catch late banners
            let count = 0;
            function repeatHarden() {
                harden();
                count++;
                if (count < 15) setTimeout(repeatHarden, 250);
            }
            repeatHarden();

            // Watch for DOM changes
            new MutationObserver(() => setTimeout(harden, 50)).observe(document.documentElement, { childList: true, subtree: true });

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
        script = r"""
        (function () {
          try {
            if (!/\.onion$/.test(location.hostname)) return;

            const realPerfNow = performance.now.bind(performance);
            const realDateNow = Date.now.bind(Date);
            const realTimeOrigin = performance.timeOrigin;

            let base = realPerfNow();
            let lastDate = realDateNow();

            function noise(){ return (Math.random() - 0.5) * 0.5; }

            function fuzzNow(){
              const delta = Math.max(0, realPerfNow() - base);
              return delta + noise();
            }

            function fuzzDateNow(){
              const v = realDateNow();
              const jittered = v + ((Math.random() < 0.333) ? -1 : (Math.random() < 0.5 ? 0 : 1));
              const out = Math.max(jittered, lastDate + 1);
              lastDate = out;
              return out;
            }

            Object.defineProperty(performance, "now", {
              value: fuzzNow, writable: false, configurable: false, enumerable: false
            });

            try {
              const perfProto = Object.getPrototypeOf(performance);
              Object.defineProperty(perfProto, "timeOrigin", {
                get(){ return realTimeOrigin; }, configurable: false
              });
            } catch {}

            Object.defineProperty(Date, "now", {
              value: fuzzDateNow, writable: false, configurable: false
            });

            const realRAF = window.requestAnimationFrame.bind(window);
            Object.defineProperty(window, "requestAnimationFrame", {
              value: (cb) => realRAF((ts) => cb(ts + noise())),
              writable: false, configurable: false
            });
          } catch (e) {
            console.warn("Timing fuzz install failed:", e);
          }
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
            const spoofedUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0";

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
        profile.setHttpUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0")
    except Exception:
        pass
    return profile
    
def make_house_icon(hex_color: str, size: int) -> QIcon:
    pm = QPixmap(size, size)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing, True)

    color = QColor(hex_color)
    linew = max(2, int(size * 0.11))
    cx, cy = size / 2, size / 2
    scale = size / 42.0

    # House geometry
    roof_w = 20 * scale
    roof_h = 10 * scale
    wall_h = 13 * scale
    wall_w = 16 * scale

    # Points for roof
    roof_peak = QPointF(cx, cy - roof_h)
    roof_left = QPointF(cx - roof_w / 2, cy)
    roof_right = QPointF(cx + roof_w / 2, cy)

    # Points for walls
    wall_top_left = QPointF(cx - wall_w / 2, cy)
    wall_top_right = QPointF(cx + wall_w / 2, cy)
    wall_bot_left = QPointF(cx - wall_w / 2, cy + wall_h)
    wall_bot_right = QPointF(cx + wall_w / 2, cy + wall_h)

    path = QPainterPath()
    # Roof
    path.moveTo(roof_left)
    path.lineTo(roof_peak)
    path.lineTo(roof_right)
    # Walls
    path.lineTo(wall_top_right)
    path.lineTo(wall_bot_right)
    path.lineTo(wall_bot_left)
    path.lineTo(wall_top_left)
    path.lineTo(roof_left)

    p.setPen(QPen(color, linew, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
    p.setBrush(Qt.NoBrush)
    p.drawPath(path)

    p.end()
    return QIcon(pm)
    
def make_shield_icon(hex_color: str, size: int) -> QIcon:
    pm = QPixmap(size, size)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing, True)
    color = QColor(hex_color)
    linew = max(2, int(size * 0.11))
    cx, cy = size / 2, size / 2
    scale = size / 42.0  # tighter fit for the shield

    # --- Shield outline path: flat top, rounded sides, pointed bottom ---
    path = QPainterPath()
    top = cy - 11 * scale
    left = cx - 14 * scale
    right = cx + 14 * scale
    bottom = cy + 14 * scale

    path.moveTo(cx, top)
    path.cubicTo(right, top + 4*scale, right, cy + 7*scale, cx, bottom)
    path.cubicTo(left, cy + 7*scale, left, top + 4*scale, cx, top)
    path.closeSubpath()

    p.setPen(QPen(color, linew, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
    p.setBrush(Qt.NoBrush)
    p.drawPath(path)

    # --- Keyhole (circle + narrow rectangle) ---
    keyhole_radius = 3.5 * scale
    keyhole_center_y = cy + 1 * scale
    p.setBrush(color)
    p.setPen(Qt.NoPen)
    p.drawEllipse(
        QPointF(cx, keyhole_center_y), keyhole_radius, keyhole_radius
    )
    rect_w = 1.7 * scale
    rect_h = 6.2 * scale
    p.drawRect(
        QRectF(
            cx - rect_w / 2,
            keyhole_center_y + keyhole_radius * 0.5,
            rect_w,
            rect_h
        )
    )

    p.end()
    return QIcon(pm)
    
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

def make_nuke_icon(hex_color: str, size: int) -> QIcon:
    """
    Returns a QIcon of the classic nuclear/radiation symbol,
    using the given accent color (hex, e.g. "#34C759") and black for the blades.
    """
    pm = QPixmap(size, size)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing, True)

    accent = QColor(hex_color)
    black = QColor("#111412")
    cx, cy = size / 2, size / 2
    radius = size * 0.48

    # Outer circle (accent with black border)
    border_width = size * 0.06
    p.setPen(QPen(black, border_width))
    p.setBrush(QBrush(accent))
    p.drawEllipse(cx - radius, cy - radius, 2 * radius, 2 * radius)

    # Inner hub (black)
    hub_r = size * 0.14
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QBrush(black))
    p.drawEllipse(cx - hub_r, cy - hub_r, 2 * hub_r, 2 * hub_r)

    # Blades (black)
    p.setBrush(QBrush(black))
    for i in range(3):
        p.save()
        p.translate(cx, cy)
        p.rotate(i * 120)
        path = [
            QPointF(0, -hub_r * 1.35),
            QPointF(size * 0.18, -size * 0.35),
            QPointF(0, -radius),
            QPointF(-size * 0.18, -size * 0.35)
        ]
        p.drawPolygon(path)
        p.restore()

    p.end()
    return QIcon(pm)

# pm now contains the green nuke/radiation icon as a QPixmap, ready for use
def make_mask_icon(hex_color: str, size: int) -> QIcon:
    pm = QPixmap(size, size)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing, True)
    color = QColor(hex_color)
    accent = QColor("#34C759")  # neon green accent

    cx, cy = size/2, size/2
    scale = size / 64.0

    # --- Head shape ---
    path = QPainterPath()
    path.moveTo(cx - 24*scale, cy - 10*scale)
    path.quadTo(cx - 30*scale, cy - 24*scale, cx - 14*scale, cy - 18*scale)
    path.quadTo(cx - 12*scale, cy - 28*scale, cx, cy - 28*scale)
    path.quadTo(cx + 12*scale, cy - 28*scale, cx + 14*scale, cy - 18*scale)
    path.quadTo(cx + 30*scale, cy - 24*scale, cx + 24*scale, cy - 10*scale)
    path.quadTo(cx + 22*scale, cy + 16*scale, cx, cy + 24*scale)
    path.quadTo(cx - 22*scale, cy + 16*scale, cx - 24*scale, cy - 10*scale)
    path.closeSubpath()

    p.setPen(QPen(accent, max(2, int(size*0.07))))
    p.setBrush(QBrush(color, Qt.SolidPattern))
    p.drawPath(path)

    # --- Eyes ---
    eye_w, eye_h = 7*scale, 5*scale
    eye_y = cy - 4*scale
    p.setBrush(accent)
    p.setPen(Qt.NoPen)
    p.drawEllipse(QRectF(cx - 10*scale - eye_w/2, eye_y, eye_w, eye_h))
    p.drawEllipse(QRectF(cx + 10*scale - eye_w/2, eye_y, eye_w, eye_h))

    # --- Mask center "nose" shadow ---
    nose_path = QPainterPath()
    nose_path.moveTo(cx, cy - 6*scale)
    nose_path.lineTo(cx + 2*scale, cy + 8*scale)
    nose_path.quadTo(cx, cy + 12*scale, cx - 2*scale, cy + 8*scale)
    nose_path.closeSubpath()
    p.setBrush(QColor("#222824"))
    p.drawPath(nose_path)

    # --- Jawline highlight (optional) ---
    p.setPen(QPen(accent, 1.5))
    jaw = QPainterPath()
    jaw.moveTo(cx - 8*scale, cy + 16*scale)
    jaw.quadTo(cx, cy + 20*scale, cx + 8*scale, cy + 16*scale)
    p.drawPath(jaw)

    p.end()
    return QIcon(pm)

def make_nav_arrow_icon(direction: str, color: str, size: int) -> QIcon:
    from PySide6.QtGui import QPolygonF
    pm = QPixmap(size, size)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing, True)
    p.setPen(Qt.NoPen)
    p.setBrush(QColor(color))
    center = QPointF(size/2, size/2)
    length = size * 0.19  # smaller than 0.28
    if direction == "left":
        points = [
            QPointF(center.x() + length, center.y() - length),
            QPointF(center.x() - length, center.y()),
            QPointF(center.x() + length, center.y() + length)
        ]
    elif direction == "right":
        points = [
            QPointF(center.x() - length, center.y() - length),
            QPointF(center.x() + length, center.y()),
            QPointF(center.x() - length, center.y() + length)
        ]
    else:
        points = []
    if points:
        p.drawPolygon(QPolygonF(points))
    p.end()
    return QIcon(pm)

def make_reload_icon(color: str, size: int) -> QIcon:
    pm = QPixmap(size, size)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing, True)
    pen_width = max(2, size // 16)
    margin = pen_width // 2 + 6  # increase margin to shrink arc
    radius = (size - 2 * margin) / 2
    center = size / 2
    # Arc: almost fully closed (like 320°)
    start_angle_deg = 135
    span_angle_deg = 320
    rect = QRectF(center - radius, center - radius, 2 * radius, 2 * radius)
    pen = QPen(QColor(color), pen_width, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin)
    p.setPen(pen)
    p.setBrush(Qt.NoBrush)
    p.drawArc(rect, int(start_angle_deg * 16), int(span_angle_deg * 16))
    # Arrowhead
    end_angle = start_angle_deg + span_angle_deg
    angle_rad = math.radians(end_angle)
    tip_x = center + radius * math.cos(angle_rad)
    tip_y = center - radius * math.sin(angle_rad)
    arrow_len = size * 0.07  # smaller arrowhead
    arrow_angle = angle_rad - math.pi / 2
    # Arrow base
    base1_x = tip_x + arrow_len * math.cos(arrow_angle + 0.3)
    base1_y = tip_y - arrow_len * math.sin(arrow_angle + 0.3)
    base2_x = tip_x + arrow_len * math.cos(arrow_angle - 0.3)
    base2_y = tip_y - arrow_len * math.sin(arrow_angle - 0.3)
    p.setBrush(QColor(color))
    arrow = QPolygonF([
        QPointF(tip_x, tip_y),
        QPointF(base1_x, base1_y),
        QPointF(base2_x, base2_y),
    ])
    p.drawPolygon(arrow)
    p.end()
    return QIcon(pm)

def make_java_icon(color: str, size: int = 48) -> QIcon:
    pm = QPixmap(size, size)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing, True)

    accent = QColor(color)
    pen = QPen(accent, size * 0.08, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin)
    p.setPen(pen)
    p.setBrush(Qt.NoBrush)

    # Draw steam (stylized)
    for i, offset in enumerate([-0.15, 0, 0.15]):
        path = QPainterPath()
        cx = size * 0.5 + offset * size
        top = size * 0.16 + i * size * 0.05
        path.moveTo(cx, top)
        path.cubicTo(cx + size*0.08, top + size*0.04, cx - size*0.08, top + size*0.10, cx, top + size*0.18)
        p.drawPath(path)

    # Draw cup
    cup_rect = QRectF(size*0.20, size*0.53, size*0.60, size*0.23)
    p.drawArc(cup_rect, 0, 16*180)  # cup rim
    body_rect = QRectF(size*0.28, size*0.63, size*0.44, size*0.18)
    p.drawArc(body_rect, 0, 16*180)  # lower arc

    # Draw saucer
    saucer_rect = QRectF(size*0.17, size*0.78, size*0.66, size*0.14)
    p.drawArc(saucer_rect, 0, 16*180)

    # Draw handle (right side)
    handle_rect = QRectF(size*0.68, size*0.62, size*0.18, size*0.22)
    p.drawArc(handle_rect, 16*40, 16*175)

    p.end()
    return QIcon(pm)
    
def make_zoom_out_icon(color: str, size: int) -> QIcon:
    pm = QPixmap(size, size)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing, True)
    pen_width = max(2, size // 10)
    pen = QPen(QColor(color), pen_width, Qt.SolidLine, Qt.RoundCap)
    p.setPen(pen)
    center = size / 2
    length = size * 0.15
    # Simple horizontal line (no circle)
    p.drawLine(center - length, center, center + length, center)
    p.end()
    return QIcon(pm)

def make_zoom_in_icon(color: str, size: int) -> QIcon:
    pm = QPixmap(size, size)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing, True)
    pen_width = max(2, size // 10)
    pen = QPen(QColor(color), pen_width, Qt.SolidLine, Qt.RoundCap)
    p.setPen(pen)
    center = size / 2
    length = size * 0.15
    # Simple horizontal line
    p.drawLine(center - length, center, center + length, center)
    # Simple vertical line
    p.drawLine(center, center - length, center, center + length)
    p.end()
    return QIcon(pm)
    
def make_fullscreen_icon(color: str, size: int) -> QIcon:
    pm = QPixmap(size, size)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing, True)
    pen = QPen(QColor(color), max(2, size//10), Qt.SolidLine, Qt.RoundCap)
    p.setPen(pen)
    gap = size*0.22
    span = size*0.13
    # Top-left
    p.drawLine(gap, gap+span, gap, gap)
    p.drawLine(gap, gap, gap+span, gap)
    # Top-right
    p.drawLine(size-gap, gap+span, size-gap, gap)
    p.drawLine(size-gap, gap, size-gap-span, gap)
    # Bottom-left
    p.drawLine(gap, size-gap-span, gap, size-gap)
    p.drawLine(gap, size-gap, gap+span, size-gap)
    # Bottom-right
    p.drawLine(size-gap, size-gap-span, size-gap, size-gap)
    p.drawLine(size-gap, size-gap, size-gap-span, size-gap)
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
            border-radius: 3px;
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
            border-radius: 12px;
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
            border-radius: 0px;
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

class TorCircuitInfoBox(QFrame):
    @staticmethod
    def flag_for_country(country_code):
        code = (country_code or '').strip().lower()
        if len(code) == 2 and code.isalpha():
            return chr(0x1F1E6 + ord(code[0]) - ord('a')) + chr(0x1F1E6 + ord(code[1]) - ord('a'))
        return "🏳️"

    def __init__(self, parent=None, on_new_identity=None):
        super().__init__(parent)
        self.setWindowFlags(self.windowFlags() | Qt.Popup | Qt.FramelessWindowHint)
        self.setStyleSheet("""
            QFrame {
                background: rgba(13,17,23,0.96);
                border: 1.3px solid #22292f;
                border-radius: 0px;
                color: #e5e7eb;
                min-width: 185px;   /* Minimum, but will grow with content */
                padding: 7px 8px 9px 8px;
            }
            QLabel {
                color: #e5e7eb;
                font-size: 13px;
                font-weight: 500;
                padding: 0 3px 0 3px;
            }
            .TorHopPill {
                background: rgba(22,24,29,0.63);
                border: 1.3px solid #23272d;
                border-radius: 0px;
                margin: 4px 0 0 0;
                padding: 4px 5px 4px 5px;
                color: #fff;
                font-size: 12px;
                letter-spacing: 0.02em;
                min-width: 0;
                word-break: break-all;
            }
            .TorHopPill b {
                color: #a7ff7a;
                font-size: 12px;
            }
            QPushButton {
                background: #34C759;
                color: #181a1b;
                border-radius: 0px;
                font-weight: bold;
                font-size: 13px;
                margin-top: 8px;
                margin-bottom: 2px;
                padding: 9px 0;
            }
            QPushButton:hover {
                background: #1aa050;
                color: #fff;
            }
        """)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(7, 7, 7, 7)
        layout.setSpacing(5)
        self.title = QLabel("<b>Current Tor Circuit for this site</b>")
        self.title.setStyleSheet("font-size:13px;padding:2px 3px 2px 3px;font-weight:700;")
        layout.addWidget(self.title)
        self.layout = layout

        self.btn_new_id = QPushButton("New Identity")
        self.btn_new_id.setCursor(Qt.PointingHandCursor)
        if on_new_identity:
            self.btn_new_id.clicked.connect(on_new_identity)
        layout.addWidget(self.btn_new_id)
        
    def set_circuit_info(self, hops):
        # Remove old labels (except title and button)
        while self.layout.count() > 2:
            item = self.layout.takeAt(1)
            w = item.widget()
            if w: w.deleteLater()
        if not hops:
            self.layout.insertWidget(1, QLabel("<i>Could not determine circuit for this site.</i>"))
        else:
            for hop in hops:
                code = hop.get('country', '').lower()
                ip = hop.get('ip', '')
                nick = hop.get('nickname', '')
                flag = self.flag_for_country(code)
                pill = QLabel(
                    f'<span>{flag}&nbsp;<b>{code}</b> <span style="color:#bbb">({ip})</span> <i style="color:#a7ff7a">{nick}</i></span>'
                )
                pill.setObjectName("TorHopPill")
                pill.setProperty("class", "TorHopPill")
                self.layout.insertWidget(self.layout.count()-1, pill)
                
class DarkelfMiniAI:
    """
    Drop-in AI security for Darkelf Mini:
    • Detects malware, phishing, network sniffing/tools
    • Triggers Panic Mode (disables JS, locks navigation, clears proxy)
    • No user setup, automatic protection
    Usage in Darkelf:
      1. Instantiate: self.ai = DarkelfMiniAI(self)
      2. On tab/page creation: self.ai.install_to_page(page)
    """

    MALWARE_PATTERNS = [
        r"(onerror\s*=|<script.*src=.*(\.php|\.exe|\.js)\??|<iframe.*src=.*hack)",
        r"(base64,|eval\(|atob\()",
        r"(document\.cookie|localStorage|sessionStorage)\s*=",
        r"(window\.open\(|location\.replace\(|location\.assign\()",
        r"(navigator\.sendBeacon|navigator\.clipboard|navigator\.mediaDevices)",
        r"(fetch\(|XMLHttpRequest|ActiveXObject)"
    ]
    PHISHING_KEYWORDS = [
        "login", "verify", "update account", "reset password",
        "bank", "security alert", "recovery", "payment", "confirm", "restricted"
    ]
    SNIFFING_HEADER_PATTERNS = [
        "x-forwarded-for", "via", "proxy-connection", "user-agent:curl", "user-agent:nmap"
    ]
    KNOWN_TOOL_SIGNATURES = [
        "wireshark", "burpsuite", "mitmproxy", "fiddler", "nmap", "tcpdump", "ettercap"
    ]
    PANIC_LOCKOUT_MS = 120_000  # 2 minutes

    def __init__(self, parent=None):
        self.parent = parent
        self.panic_mode = False
        self._js_state_per_tab = {}  # idx -> bool

    def install_to_page(self, page):
        # Keep your existing injection API to remain zero-trace
        page.inject_script(
            self._js_phishing_malware_detector(),
            injection_point=QWebEngineScript.DocumentReady,
            subframes=True,
        )
        page.inject_script(
            self._js_sniffer_detector(),
            injection_point=QWebEngineScript.DocumentReady,
            subframes=True,
        )

    def monitor_network(self, url, headers):
        if self.panic_mode:
            return
        for h, v in headers.items():
            for patt in self.SNIFFING_HEADER_PATTERNS:
                if patt in str(h).lower() or patt in str(v).lower():
                    self.trigger_panic(f"Sniffing header detected: {h}: {v}")
                    return
        for sig in self.KNOWN_TOOL_SIGNATURES:
            if sig in (url or "").lower() or any(sig in str(v).lower() for v in headers.values()):
                self.trigger_panic(f"Known tool detected: {sig}")
                return

    def trigger_panic(self, reason=""):
        if self.panic_mode:
            return
        self.panic_mode = True

        # Notify parent UI (Option B wiring)
        if self.parent and hasattr(self.parent, "set_protection_indicator"):
            try:
                self.parent.set_protection_indicator(panic=True, reason=reason)
            except Exception:
                pass

        self._block_javascript()
        self._block_navigation()
        self._disconnect_proxy()
        self._show_panic_alert(reason)
        # Qt timer (thread-safe for UI); same lockout duration
        QTimer.singleShot(self.PANIC_LOCKOUT_MS, self._release_panic)

    def _release_panic(self):
        self.panic_mode = False

        # Notify parent UI (Option B wiring)
        if self.parent and hasattr(self.parent, "set_protection_indicator"):
            try:
                self.parent.set_protection_indicator(panic=False)
            except Exception:
                pass

        self._restore_javascript()
        self._restore_navigation()
        self._show_panic_release()

    def _iter_tabs(self):
        tw = getattr(self.parent, "tab_widget", None)
        if not tw:
            return []
        return [tw.widget(i) for i in range(tw.count())]

    def _block_javascript(self):
        for idx, w in enumerate(self._iter_tabs()):
            settings = getattr(w, "settings", lambda: None)()
            if not settings:
                continue
            # save current state once
            if idx not in self._js_state_per_tab:
                self._js_state_per_tab[idx] = settings.testAttribute(QWebEngineSettings.JavascriptEnabled)
            settings.setAttribute(QWebEngineSettings.JavascriptEnabled, False)

    def _restore_javascript(self):
        for idx, w in enumerate(self._iter_tabs()):
            settings = getattr(w, "settings", lambda: None)()
            if not settings:
                continue
            prev = self._js_state_per_tab.get(idx)
            if prev is None:
                prev = bool(getattr(self.parent, "javascript_enabled", True))
            settings.setAttribute(QWebEngineSettings.JavascriptEnabled, prev)
        self._js_state_per_tab.clear()

    def _block_navigation(self):
        if hasattr(self.parent, "tab_widget") and hasattr(self.parent, "custom_homepage_html"):
            for w in self._iter_tabs():
                setHtml = getattr(w, "setHtml", None)
                if callable(setHtml):
                    try:
                        setHtml(self.parent.custom_homepage_html())
                    except Exception:
                        pass  # zero-trace

    def _restore_navigation(self):
        # Minimal, non-invasive: reload each tab if possible
        for w in self._iter_tabs():
            reload_ = getattr(w, "reload", None)
            if callable(reload_):
                try:
                    reload_()
                except Exception:
                    pass

    def _disconnect_proxy(self):
        import os, re
        os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = re.sub(
            r'\s*--proxy-server="[^"]*"', '',
            os.environ.get("QTWEBENGINE_CHROMIUM_FLAGS", "")
        )

    def _show_panic_alert(self, reason):
        if self.parent:
            try:
                QMessageBox.critical(
                    self.parent, "PANIC MODE ACTIVATED",
                    f"Malware/Phishing/Sniffing detected.\n\n{reason}\n\nAll browsing locked for {self.PANIC_LOCKOUT_MS//1000} seconds."
                )
            except Exception:
                pass

    def _show_panic_release(self):
        if self.parent:
            try:
                QMessageBox.information(
                    self.parent, "Panic Mode Released",
                    "Panic lockout ended. Browsing functions are restored."
                )
            except Exception:
                pass

    def _js_phishing_malware_detector(self):
        js = r"""
        (() => {
            const phishingWords = %s;
            const malwarePatterns = [%s].map(r => new RegExp(r, "i"));
            let panic = false;

            function scanForms() {
                const forms = document.querySelectorAll("form");
                for (const f of forms) {
                    const txt = (f.textContent || "") + " " + (f.outerHTML || "");
                    for (const w of phishingWords) {
                        if (txt.toLowerCase().includes(w)) {
                            window.__darkelf_panic_trigger && window.__darkelf_panic_trigger("Phishing form detected: " + w);
                            panic = true;
                            return;
                        }
                    }
                }
            }

            function scanScripts() {
                const scripts = document.querySelectorAll("script");
                for (const s of scripts) {
                    const code = s.textContent || s.src || "";
                    for (const r of malwarePatterns) {
                        if (r.test(code)) {
                            window.__darkelf_panic_trigger && window.__darkelf_panic_trigger("Malware script detected.");
                            panic = true;
                            return;
                        }
                    }
                }
            }

            function scanLinks() {
                const links = document.querySelectorAll("a[href]");
                for (const l of links) {
                    const href = l.getAttribute("href") || "";
                    for (const w of phishingWords) {
                        if (href.toLowerCase().includes(w)) {
                            window.__darkelf_panic_trigger && window.__darkelf_panic_trigger("Phishing link detected: " + href);
                            panic = true;
                            return;
                        }
                    }
                }
            }

            function runScans() {
                if (panic) return;
                scanForms(); scanScripts(); scanLinks();
            }

            runScans();
            document.addEventListener("DOMContentLoaded", runScans);
            setTimeout(runScans, 1500);
        })();
        """ % (
            repr(self.PHISHING_KEYWORDS),
            ','.join([repr(p) for p in self.MALWARE_PATTERNS])
        )
        return js

    def _js_sniffer_detector(self):
        js = r"""
        (() => {
            function trigger(reason) {
                window.__darkelf_panic_trigger && window.__darkelf_panic_trigger(reason);
            }
            if (window.RTCPeerConnection || window.webkitRTCPeerConnection) {
                trigger("WebRTC detected (possible sniffing).");
            }
            if (window.Wireshark || window.BurpSuite || window.Fiddler) {
                trigger("Known sniffing tool detected.");
            }
            let evalCount = 0;
            const origEval = window.eval;
            window.eval = function(code) {
                evalCount++; if (evalCount > 3) trigger("Excessive eval() usage (possible malware).");
                return origEval(code);
            };
            let funcCount = 0;
            const OrigFunc = Function;
            window.Function = function(...args) {
                funcCount++; if (funcCount > 3) trigger("Excessive Function() usage (possible malware).");
                return OrigFunc(...args);
            };
        })();
        """
        return js
        
def robust_memory_overwrite(obj, n_rounds=2, _visited=None):
    if _visited is None:
        _visited = set()
    oid = id(obj)
    if oid in _visited:
        return
    _visited.add(oid)

    # Handle dict-like objects
    if isinstance(obj, dict):
        for k in list(obj.keys()):
            v = obj[k]
            # Recursively scrub values
            robust_memory_overwrite(v, n_rounds, _visited)
            # Overwrite value with random bytes/string
            if isinstance(v, (str, bytes, bytearray)):
                obj[k] = secrets.token_hex(32)
            else:
                obj[k] = None

    # Handle list/tuple/set
    elif isinstance(obj, (list, tuple, set)):
        for i, v in enumerate(list(obj)):
            robust_memory_overwrite(v, n_rounds, _visited)
            # Overwrite with junk if possible
            if isinstance(obj, list):
                obj[i] = secrets.token_hex(32)
        # For sets, rebuild as junk
        if isinstance(obj, set):
            obj.clear()
            [obj.add(secrets.token_hex(32)) for _ in range(6)]

    # Overwrite bytes/bytearray
    elif isinstance(obj, (bytes, bytearray)):
        for _ in range(n_rounds):
            junk = secrets.token_bytes(len(obj))
            if isinstance(obj, bytearray):
                obj[:] = junk

    # Overwrite string
    elif isinstance(obj, str):
        obj = secrets.token_hex(len(obj))

    # Overwrite attributes of objects (but not Qt/C++ or builtins)
    elif hasattr(obj, "__dict__"):
        for k in list(vars(obj).keys()):
            v = getattr(obj, k, None)
            # Recursively scrub
            robust_memory_overwrite(v, n_rounds, _visited)
            # Overwrite field with junk
            if isinstance(v, (str, bytes, bytearray)):
                try:
                    setattr(obj, k, secrets.token_hex(32))
                except Exception:
                    pass
            elif isinstance(v, (list, dict, set, tuple)):
                try:
                    setattr(obj, k, type(v)())
                except Exception:
                    pass
            else:
                try:
                    setattr(obj, k, None)
                except Exception:
                    pass

    # Final fallback: try to overwrite via delattr
    else:
        try:
            for attr in dir(obj):
                if not attr.startswith("__"):
                    delattr(obj, attr)
        except Exception:
            pass
            
class WipeLineEdit(QLineEdit):
    def __init__(self, parent=None, wipe_callback=None):
        super().__init__(parent)
        self._wipe_callback = wipe_callback
    def pasteEvent(self, event):
        super().pasteEvent(event)
    def copy(self):
        super().copy()

            
class Darkelf(QMainWindow):
    def __init__(self, start_url: str = "home"):
        super().__init__()
        SuperHardenedPage.setup_ssl_configuration()
        print("[boot] Darkelf starting…")
        
        self._stream_to_circuit = {}  # stream_id -> circ_id
        self._circuit_paths = {}      # circ_id -> [fp1, fp2, fp3]
        self._circuit_infobox = None
        self.settings = EphemeralSettings()
        self.javascript_enabled = self.settings.value("javascript_enabled", False, type=bool)
        self.ai = DarkelfMiniAI(self)
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
        self._ipguard = IPLeakGuard(self)  # <-- NEW LINE
        DarkelfHardenedProfile.install(self.web_profile, remove_iframes=True)
        self._composite = CompositeInterceptor(self._adblock, self._strip, self._ipguard, parent=self)  # <-- Add here
        self.web_profile.setUrlRequestInterceptor(self._composite)

        # UI
        self.init_ui()
        self.init_shortcuts()
                
        # First tab: homepage or provided URL
        self.create_new_tab(start_url)
        
    def prompt_new_identity(self):
        # Hide the infobox while prompting
        if self._circuit_infobox:
            self._circuit_infobox.hide()
        reply = QMessageBox.question(
            self,
            "New Identity",
            "This will clear all cookies/storage for this tab, request a new Tor circuit, and reload.\n\nContinue?",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self.new_identity_for_current_tab()
            
    def _on_circ_event(self, event):
        pass

    def _on_stream_event(self, event):
        pass
        
    def _show_audit_overlay(self):
        dlg = QDialog(self)
        dlg.setWindowTitle("Audit Overlay – Privacy Self-Test")
        dlg.setMinimumSize(700, 500)
        v = QVBoxLayout(dlg)
        text = QTextEdit()
        text.setReadOnly(True)
        # You can add more info here (blocked requests, spoofed values)
        info = "Fingerprint Spoofing:\n"
        info += "- User-Agent: Mozilla/5.0 (Windows NT 10.0; ...)\n"
        info += "- WebGL/Canvas: Randomized/noise\n"
        info += "- Plugins/MimeTypes: Empty\n"
        info += "- Storage: Disabled\n"
        info += "- WebRTC: Blocked\n"
        info += "- ...\n"
        info += "\nBlocked requests are not logged to disk for privacy. (You can add in-memory logging if desired.)"
        text.setText(info)
        v.addWidget(text)
        btn = QPushButton("Close", dlg); btn.clicked.connect(dlg.accept)
        v.addWidget(btn)
        dlg.exec()
        
    def _ensure_anti_spoof_border(self, show: bool):
        # Only create once
        if not hasattr(self, "_spoof_border_overlay"):
            self._spoof_border_overlay = QWidget(self)
            self._spoof_border_overlay.setAttribute(Qt.WA_TransparentForMouseEvents)
            self._spoof_border_overlay.setWindowFlags(Qt.FramelessWindowHint | Qt.Tool)
            self._spoof_border_overlay.setStyleSheet("""
                background: rgba(0,0,0,0);
                border: 5px solid #34C759;  /* Neon green accent */
                border-radius: 0px;
            """)
            self._spoof_border_overlay.hide()
        if show:
            self._spoof_border_overlay.setGeometry(self.rect())
            self._spoof_border_overlay.raise_()
            self._spoof_border_overlay.show()
        else:
            self._spoof_border_overlay.hide()
            
    def resizeEvent(self, event):
        if hasattr(self, "_spoof_border_overlay") and self._spoof_border_overlay.isVisible():
            self._spoof_border_overlay.setGeometry(self.rect())
        return super().resizeEvent(event)
    
    def build_web_profile(self):
        profile = QWebEngineProfile("darkelf", self)
        profile.setHttpCacheType(QWebEngineProfile.MemoryHttpCache)
        profile.setPersistentCookiesPolicy(QWebEngineProfile.NoPersistentCookies)
        profile.setSpellCheckEnabled(False)
        profile.setHttpUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0")

        # Harden QWebEngineSettings
        settings = profile.settings()
        settings.setAttribute(QWebEngineSettings.JavascriptCanOpenWindows, False)
        settings.setAttribute(QWebEngineSettings.JavascriptCanAccessClipboard, False)
        settings.setAttribute(QWebEngineSettings.LocalContentCanAccessRemoteUrls, False)
        settings.setAttribute(QWebEngineSettings.XSSAuditingEnabled, True)
        settings.setAttribute(QWebEngineSettings.ErrorPageEnabled, False)
        settings.setAttribute(QWebEngineSettings.WebGLEnabled, False)
        settings.setAttribute(QWebEngineSettings.WebRTCPublicInterfacesOnly, False)
        settings.setAttribute(QWebEngineSettings.AutoLoadImages, True)
        settings.setAttribute(QWebEngineSettings.PluginsEnabled, False)
        settings.setAttribute(QWebEngineSettings.HyperlinkAuditingEnabled, False)
        settings.setAttribute(QWebEngineSettings.FullScreenSupportEnabled, True)
        settings.setAttribute(QWebEngineSettings.SpatialNavigationEnabled, False)
        settings.setAttribute(QWebEngineSettings.AllowWindowActivationFromJavaScript, False)
        settings.setAttribute(QWebEngineSettings.ScreenCaptureEnabled, False)
        settings.setAttribute(QWebEngineSettings.PdfViewerEnabled, False)
        settings.setAttribute(QWebEngineSettings.LocalContentCanAccessFileUrls, False)
        settings.setAttribute(QWebEngineSettings.DnsPrefetchEnabled, False)
        settings.setAttribute(QWebEngineSettings.AutoLoadIconsForPage, False)
        settings.setAttribute(QWebEngineSettings.TouchIconsEnabled, False)
        settings.setAttribute(QWebEngineSettings.AllowRunningInsecureContent, False)
        settings.setAttribute(QWebEngineSettings.AllowGeolocationOnInsecureOrigins, False)
        settings.setAttribute(QWebEngineSettings.PlaybackRequiresUserGesture, True)

        return profile
        
    def eventFilter(self, obj, ev):
        if sys.platform != "darwin":
            return False  # never swallow; let Qt continue

        try:
            et = ev.type()
            if et in (QEvent.KeyPress, QEvent.KeyRelease) and ev.key() == Qt.Key_CapsLock:
                if not ev.isAutoRepeat() and et == QEvent.KeyRelease:
                    self._caps_on = not self._caps_on
                    self._caps_toggled_at = time.monotonic()
                return False

            if et == QEvent.KeyPress:
                if ev.isAutoRepeat():
                    return False
                mods = ev.modifiers()
                if mods & (Qt.ControlModifier | Qt.AltModifier | Qt.MetaModifier):
                    return False
                text = ev.text() or ""
                if len(text) == 1 and "a" <= text <= "z":
                    toggled_recently = (time.monotonic() - self._caps_toggled_at) < 0.22
                    want_upper = bool(self._caps_on) ^ bool(mods & Qt.ShiftModifier)
                    if toggled_recently and want_upper:
                        ch = text
                        QTimer.singleShot(0, lambda: self._fix_last(ch))
                        return False
            return False
        except Exception:
            return False

    def _fix_last(self, lower_ch: str):
        w = QApplication.focusWidget()

        if isinstance(w, QLineEdit):
            val = w.text()
            if val.endswith(lower_ch):
                w.setText(val[:-1] + lower_ch.upper())
                w.setCursorPosition(len(val))
            return

        if isinstance(w, (QTextEdit, QPlainTextEdit)):
            cursor = w.textCursor()
            cursor.movePosition(QTextCursor.Left, QTextCursor.MoveAnchor, 1)
            cursor.movePosition(QTextCursor.Right, QTextCursor.KeepAnchor, 1)
            if cursor.selectedText() == lower_ch:
                cursor.insertText(lower_ch.upper())
                w.setTextCursor(cursor)
            return

        # If you have a helper on your window to get the current QWebEngineView:
        v = getattr(self.window, "current_view", lambda: None)()
        if v and hasattr(v, "page"):
            upper = lower_ch.upper()
            js = f"""
            (function(){{
              const el = document.activeElement;
              if (!el) return;
              const isInput = el.tagName === 'INPUT' && el.type === 'text';
              const isTA = el.tagName === 'TEXTAREA';
              const isCE = el.isContentEditable;
              if (!(isInput || isTA || isCE)) return;
              const getVal = n => (n.value !== undefined) ? n.value : n.innerText;
              const setVal = (n,s) => {{
                if (n.value !== undefined) {{
                  n.value = s;
                  if (n.setSelectionRange) n.setSelectionRange(n.value.length, n.value.length);
                }} else {{
                  n.innerText = s;
                  const sel = window.getSelection();
                  if (sel && n.lastChild) sel.collapse(n.lastChild, n.lastChild.length);
                }}
              }};
              const v = getVal(el);
              if (v && v[v.length-1] === {lower_ch!r}) setVal(el, v.slice(0,-1) + {upper!r});
            }})();
            """
            v.page().runJavaScript(js)
            
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

            try:
                self._stream_to_circ = {}  # stream_id -> circ_id
                self._circ_paths = {}      # circ_id -> [fp1, fp2, fp3...]
                self.controller.add_event_listener(self._on_circ_event, stem.control.EventType.CIRC)
                self.controller.add_event_listener(self._on_stream_event, stem.control.EventType.STREAM)
                print("[Darkelf] Tor event listeners registered.")
            except OSError as e:
                QMessageBox.critical(None, "Tor Error", f"Failed to start Tor: {e}")

        except Exception as e:
            print(f"[Darkelf] start_tor error: {e}")

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
            
    def get_tor_circuit_for_current_tab(self):
        if not self.controller:
            return []
        try:
            circuits = [c for c in self.controller.get_circuits() if c.status == 'BUILT']
            if not circuits:
                return []
            circ = circuits[-1]  # Most recent built circuit
            path_info = []
            for fp, _ in circ.path:
                desc = self.controller.get_network_status(fp)
                if desc:
                    ip = desc.address
                    # Lookup the country code using Tor's ip-to-country mapping (may return '??' or fail)
                    try:
                        country = self.controller.get_info(f"ip-to-country/{ip}")
                    except Exception:
                        country = "Unknown"
                # Tor often returns '??' for unknown
                    if not country or country == "??":
                        country = "Unknown"
                    path_info.append({
                        'nickname': desc.nickname,
                        'ip': ip,
                        'country': country
                    })
            return path_info
        except Exception as e:
            print("[Tor Circuit] Error:", e)
            return []
            
    def show_circuit_and_new_identity(self):
        # Show circuit info dialog first
        circuit_info = self.get_tor_circuit_for_current_tab()
        TorCircuitDialog(circuit_info, self).exec()
        # Then proceed as before
        self.new_identity_for_current_tab()
        
    def init_shortcuts(self):
        """
        Cross-platform browser shortcuts for Windows, Linux, macOS (M series included).
        Uses both StandardKey and explicit QKeySequence to maximize compatibility.
        """

        def bind(seq, handler):
            sc = QShortcut(QKeySequence(seq), self)
            sc.setContext(Qt.ApplicationShortcut)
            sc.activated.connect(handler)
            return sc

        # --- Navigation ---
        bind(QKeySequence.StandardKey.Back, self.go_back)
        bind(QKeySequence.StandardKey.Forward, self.go_forward)
        bind("Alt+Left", self.go_back)
        bind("Alt+Right", self.go_forward)
        bind("Ctrl+[", self.go_back)
        bind("Ctrl+]", self.go_forward)
        bind("Meta+[", self.go_back)
        bind("Meta+]", self.go_forward)

        # --- Reload / Hard Reload ---
        bind(QKeySequence.StandardKey.Refresh, self.reload_page)  # F5/Cmd+R/Ctrl+R
        bind("Ctrl+R", self.reload_page)
        bind("Meta+R", self.reload_page)
        bind("Ctrl+Shift+R", getattr(self, "hard_reload", self.reload_page))
        bind("Meta+Shift+R", getattr(self, "hard_reload", self.reload_page))
        bind("Shift+F5", getattr(self, "hard_reload", self.reload_page))

        # --- Tabs & Window ---
        bind(QKeySequence.StandardKey.AddTab, self.create_new_tab)
        bind("Ctrl+T", self.create_new_tab)
        bind("Meta+T", self.create_new_tab)
        bind(QKeySequence.StandardKey.Close, lambda: self.close_tab(self.tab_widget.currentIndex()))
        bind("Ctrl+W", lambda: self.close_tab(self.tab_widget.currentIndex()))
        bind("Meta+W", lambda: self.close_tab(self.tab_widget.currentIndex()))
        bind("Ctrl+Shift+T", getattr(self, "reopen_tab", lambda: None))  # Add handler if you want "Reopen Tab"
        bind("Meta+Shift+T", getattr(self, "reopen_tab", lambda: None))
        bind("Ctrl+N", getattr(self, "new_window", lambda: None))
        bind("Meta+N", getattr(self, "new_window", lambda: None))
        bind("Ctrl+Shift+W", self.close)
        bind("Meta+Shift+W", self.close)

        # --- Address Bar (Omnibox/Search) ---
        bind("Ctrl+L", self.focus_address_bar)
        bind("Meta+L", self.focus_address_bar)
        bind("F6", self.focus_address_bar)
        bind("Alt+D", self.focus_address_bar)

        # --- Find, Print, Save ---
        bind("Ctrl+F", getattr(self, "open_find_dialog", lambda: None))
        bind("Meta+F", getattr(self, "open_find_dialog", lambda: None))
        bind("Ctrl+P", getattr(self, "print_page", lambda: None))
        bind("Meta+P", getattr(self, "print_page", lambda: None))
        bind("Ctrl+S", getattr(self, "save_page", lambda: None))
        bind("Meta+S", getattr(self, "save_page", lambda: None))

        # --- History ---
        if sys.platform == "darwin":
            bind("Meta+Y", self.view_history)  # Safari/Chrome on macOS
        else:
            bind("Ctrl+H", self.view_history)

        # --- Downloads ---
        bind("Ctrl+J", getattr(self, "open_downloads", lambda: None))
        bind("Meta+Shift+J", getattr(self, "open_downloads", lambda: None))

        # --- Dev Tools ---
        bind("F12", getattr(self, "open_devtools", lambda: None))
        bind("Ctrl+Shift+I", getattr(self, "open_devtools", lambda: None))
        bind("Meta+Alt+I", getattr(self, "open_devtools", lambda: None))

        # --- Zoom ---
        bind(QKeySequence.StandardKey.ZoomIn, self.zoom_in)
        bind(QKeySequence.StandardKey.ZoomOut, self.zoom_out)
        bind("Ctrl+=", self.zoom_in)
        bind("Ctrl++", self.zoom_in)
        bind("Meta+=", self.zoom_in)
        bind("Meta++", self.zoom_in)
        bind("Ctrl+-", self.zoom_out)
        bind("Meta+-", self.zoom_out)
        bind("Ctrl+0", getattr(self, "reset_zoom", lambda: None))
        bind("Meta+0", getattr(self, "reset_zoom", lambda: None))

        # --- Fullscreen ---
        bind(QKeySequence.StandardKey.FullScreen, self.toggle_full_screen)
        bind("F11", self.toggle_full_screen)
        bind("Ctrl+Meta+F", self.toggle_full_screen)  # macOS

        # --- Select All, Copy, Paste, Cut ---
        bind("Ctrl+A", getattr(self, "select_all", lambda: None))
        bind("Meta+A", getattr(self, "select_all", lambda: None))
        bind("Ctrl+C", getattr(self, "copy_selection", lambda: None))
        bind("Meta+C", getattr(self, "copy_selection", lambda: None))
        bind("Ctrl+V", getattr(self, "paste_clipboard", lambda: None))
        bind("Meta+V", getattr(self, "paste_clipboard", lambda: None))
        bind("Ctrl+X", getattr(self, "cut_selection", lambda: None))
        bind("Meta+X", getattr(self, "cut_selection", lambda: None))

        # --- Extra: Omnibox/search bar Paste and Go (optional) ---
        bind("Ctrl+Shift+V", getattr(self, "paste_and_go", lambda: None))
        bind("Meta+Shift+V", getattr(self, "paste_and_go", lambda: None))
        

        sc_audit = QShortcut(QKeySequence("Ctrl+Alt+A"), self)
        sc_audit.setContext(Qt.ApplicationShortcut)
        sc_audit.activated.connect(self._show_audit_overlay)

        if platform.system() == "Darwin":
            sc_audit_mac = QShortcut(QKeySequence("Meta+Alt+A"), self)
            sc_audit_mac.setContext(Qt.ApplicationShortcut)
            sc_audit_mac.activated.connect(self._show_audit_overlay)
        
    def focus_address_bar(self):
        """Focuses the search/omnibox/address bar."""
        self.search_bar.setFocus()

    def init_ui(self):
        self.setWindowTitle("")
        self.resize(1200, 800)
        self.tab_widget = QTabWidget()
        self.setCentralWidget(self.tab_widget)
        self.tab_widget.tabCloseRequested.connect(self.close_tab)
        self.tab_widget.setMovable(False)
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
        
    def _btn(self, slot, icon, tip=""):
        b = QToolButton(self)
        b.setIcon(icon)
        b.clicked.connect(slot)
        b.setAutoRaise(True)
        if tip:
            b.setToolTip(tip)
        return b
        
    def create_toolbar(self):
        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setFloatable(False)
        toolbar.setIconSize(QSize(24, 24))
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
                font-size: 18px;
            }}
            QToolButton:hover {{
                background: rgba(24,247,122,0.14);
                border-color: {THEME['accent']};
                color: {THEME['accent']};
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

        nav_icon_size = 24

        # Use new icon functions
        back_button    = self._btn(self.go_back, make_nav_arrow_icon('left', THEME['text'], nav_icon_size), "Back")
        forward_button = self._btn(self.go_forward, make_nav_arrow_icon('right', THEME['text'], nav_icon_size), "Forward")
        reload_button  = self._btn(self.reload_page, make_reload_icon(THEME['text'], nav_icon_size), "Reload")

        mask_icon_size = 36
        
        new_id_button = self._btn(
            self.on_mask_button_clicked,
            make_mask_icon(THEME['accent'], mask_icon_size),
            "New Identity / Show Tor Circuit"
        )
        self.new_id_button = new_id_button
        
        self.act_clear = QAction(make_nuke_icon(THEME['accent'], nav_icon_size), "Clear All Data", self)
        self.act_clear.triggered.connect(self.clear_all_data)
        home_button = self._btn(self.load_homepage, make_house_icon(THEME['accent'], nav_icon_size), "Home")

        # --- REORDER ICONS FOR CONSISTENCY AND LOGIC ---
        toolbar.addWidget(back_button)
        toolbar.addWidget(forward_button)
        toolbar.addWidget(reload_button)
        toolbar.addWidget(home_button)
        toolbar.addSeparator()
        self.search_bar = QLineEdit(self)
        self.search_bar.setObjectName("omni")
        self.search_bar.setPlaceholderText("Search or enter URL")
        self.search_bar.returnPressed.connect(self.search_or_load_url)
        self.search_bar.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.search_bar.setContextMenuPolicy(Qt.CustomContextMenu)
        self.search_bar.customContextMenuRequested.connect(self.show_context_menu)
        toolbar.addWidget(self.search_bar)
        toolbar.addSeparator()
        toolbar.addAction(self.act_clear)         # Nuke/Clear All Data
        toolbar.addWidget(new_id_button)          # Mask/New Identity
        # JavaScript Protection Toggle Button (always clickable)
        self.java_protect_button = self._btn(
            self.toggle_javascript_via_button,
            make_java_icon("#22c55e" if not self.javascript_enabled else "#228be6"),
            "Java Protection: Disabled (click to enable JavaScript)" if not self.javascript_enabled else "Java Enabled (click to disable for protection)"
        )
        self.java_protect_button.setEnabled(True)
        toolbar.addWidget(self.java_protect_button)
        # Protection indicator (starts enabled/green)
        self._protect_button = self._btn(
            getattr(self, "open_security_panel", lambda: None),
            make_shield_icon("#22c55e", nav_icon_size),
            "Darkelf Protection: Enabled"
        )
        toolbar.addWidget(self._protect_button)
        toolbar.addSeparator()
        zoom_in_button  = self._btn(self.zoom_in, make_zoom_in_icon(THEME['text'], nav_icon_size), "Zoom In")
        zoom_out_button = self._btn(self.zoom_out, make_zoom_out_icon(THEME['text'], nav_icon_size), "Zoom Out")
        full_button = self._btn(self.toggle_full_screen, make_fullscreen_icon(THEME['text'], nav_icon_size), "Full Screen")
        toolbar.addWidget(zoom_out_button)
        toolbar.addWidget(zoom_in_button)
        toolbar.addWidget(full_button)

        self.addToolBar(toolbar)
        self._apply_shortcuts()
        return toolbar
        
    def on_mask_button_clicked(self):
        if self._circuit_infobox and self._circuit_infobox.isVisible():
            self._circuit_infobox.hide()
            return
        hops = self.get_tor_circuit_for_current_tab()
        if not self._circuit_infobox:
            self._circuit_infobox = TorCircuitInfoBox(self, on_new_identity=self.prompt_new_identity)
        self._circuit_infobox.set_circuit_info(hops)
        btn = self.new_id_button
        pos = btn.mapToGlobal(QPoint(0, btn.height()))
        self._circuit_infobox.move(pos)
        self._circuit_infobox.adjustSize()
        self._circuit_infobox.show()
        
    def _apply_shortcuts(self):
        pass  # superseded by init_shortcuts()

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
       
        # --- Add "Clear All Data" here ---
        act_cache = QAction("Clear Cache", self); act_cache.triggered.connect(self.clear_cache); sec.addAction(act_cache)
        act_cookies = QAction("Clear Cookies", self); act_cookies.triggered.connect(self.clear_cookies); sec.addAction(act_cookies)
        act_clear_all = QAction("Clear All Data", self)
        act_clear_all.triggered.connect(self.clear_all_data)
        sec.addAction(act_clear_all)

        hist = menu_bar.addMenu("History")
        vh = QAction("View History", self); vh.triggered.connect(self.view_history); hist.addAction(vh)
        ch = QAction("Clear History", self); ch.triggered.connect(self.clear_history); hist.addAction(ch)

        about = menu_bar.addMenu("About")
        wiki_action = QAction("Wiki", self)
        wiki_action.triggered.connect(lambda: self.create_new_tab("https://github.com/Darkelf2024/Darkelf-Mini-Browser/wiki"))
        about.addAction(wiki_action)
        
    def set_protection_indicator(self, *, panic: bool, reason: str = ""):
        """Green when enabled, red on panic."""
        if not hasattr(self, "_protect_button") or self._protect_button is None:
            return
        if panic:
            icon = make_shield_icon("#ff3b30", getattr(self, "nav_icon_size", 18))  # red
            tip = "Darkelf Protection: PANIC MODE\n" + (reason or "")
        else:
            icon = make_shield_icon("#22c55e", getattr(self, "nav_icon_size", 18))  # green
            tip = "Darkelf Protection: Enabled"
        self._protect_button.setIcon(icon)
        self._protect_button.setToolTip(tip)

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

  <script>
  (function() {
      if (!navigator.platform.toLowerCase().includes('mac')) return;
      let lastCapsToggle = 0, capsOn = false;
      document.addEventListener('keydown', function(ev) {
          if (ev.key === "CapsLock") {
              capsOn = !capsOn;
              lastCapsToggle = Date.now();
          }
      });
      function fixInput(e) {
          let input = e.target;
          if (input.tagName !== "INPUT" || input.type !== "text") return;
          let val = input.value;
          if (!val) return;
          let now = Date.now();
          if (now - lastCapsToggle < 500 && capsOn) {
              let last = val[val.length - 1];
              if (last && last >= "a" && last <= "z") {
                  input.value = val.slice(0, -1) + last.toUpperCase();
                  input.setSelectionRange(input.value.length, input.value.length);
              }
          }
      }
      document.addEventListener('input', fixInput, true);
  })();
  </script>
</body>
</html>
"""

    def create_new_tab(self, url="home"):
        view = QWebEngineView()
        page = SuperHardenedPage(self.web_profile, view)
        self.ai.install_to_page(page)
        view.setPage(page)
        view.settings().setAttribute(QWebEngineSettings.JavascriptEnabled, self.javascript_enabled)
        view.loadFinished.connect(self._update_tab_title)
        view.urlChanged.connect(self.update_url_bar)

        # ---- PASTE THESE TWO LINES HERE ----
        view.setContextMenuPolicy(Qt.CustomContextMenu)
        view.customContextMenuRequested.connect(self.show_context_menu)
        # ------------------------------------

        if url == "home":
            view.setHtml(self.custom_homepage_html()); title = "Darkelf"
        else:
            view.setUrl(QUrl(url)); title = "New Tab"
        idx = self.tab_widget.addTab(view, title)
        self.tab_widget.setCurrentIndex(idx)
        self.tab_histories[idx] = []  # Initialize per-tab history
        return view
    
    def close_tab(self, index):
        if index < 0:
            return
        w = self.tab_widget.widget(index)
        self.tab_widget.removeTab(index)  # Remove FIRST
        if isinstance(w, QWebEngineView):
            try:
                # Before closing, wipe sensitive DOM
                wipe_js = """
                (function(){
                    function wipeInputs() {
                        let junk = '';
                        for (let i=0; i<128; ++i) junk += String.fromCharCode(33 + Math.random()*93);
                        document.querySelectorAll('input,textarea').forEach(e => { e.value = junk; });
                        document.querySelectorAll('[contenteditable="true"]').forEach(e => { e.innerText = junk; });
                    }
                    try { wipeInputs(); } catch(e){}
                })();
                """
                w.page().runJavaScript(wipe_js)
            except Exception:
                pass
            try:
                p = w.page()
                if p:
                    p.setParent(None)
                    w.setPage(None)
                    p.deleteLater()
            except RuntimeError:
                pass
        if index in self.tab_histories:
            del self.tab_histories[index]
        if self.tab_widget.count() == 0:
            self.create_new_tab("home")
        try:
            w.deleteLater()
        except Exception:
            pass
        
    def current_view(self):
        w = self.tab_widget.currentWidget()
        return w if isinstance(w, QWebEngineView) else None

    def show_context_menu(self, pos):
        v = self.current_view()
        if not v:
            return
        page = v.page()
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

        ICON_SIZE = 16
        menu.setStyleSheet("""
            QMenu { ... }
            ...  # your style
        """)

        act_back    = menu.addAction(make_text_icon('◄', ICON_SIZE), "Back",    self.go_back)
        act_forward = menu.addAction(make_text_icon('►', ICON_SIZE), "Forward", self.go_forward)
        act_reload  = menu.addAction(make_text_icon('↺', ICON_SIZE), "Reload",  self.reload_page)
        act_back.setEnabled(v.history().canGoBack())
        act_forward.setEnabled(v.history().canGoForward())
        menu.addSeparator()

        if data and hasattr(data, "linkUrl") and data.linkUrl().isValid():
            menu.addAction(make_text_icon('⤴', ICON_SIZE), "Open Link in New Tab",
                        lambda url=data.linkUrl(): self.create_new_tab(url.toString()))
            menu.addAction("Copy Link Address",
                        lambda url=data.linkUrl():   QGuiApplication.clipboard().setText(url.toString()))
            menu.addSeparator()
        # --- Detect if focus is on search bar ---
        focus = QApplication.focusWidget()
        if focus == self.search_bar:
            menu.addAction("Copy", self.search_bar.copy)
            menu.addAction("Paste", self.search_bar.paste)
            menu.addAction("Paste and Go", lambda: (self.search_bar.paste(), self.search_or_load_url()))
            menu.addAction("Clear", self.search_bar.clear)
            menu.addAction("Clear Clipboard", self.wipe_clipboard_all_modes_now)
        else:
            menu.addAction("Copy", lambda: page.triggerAction(QWebEnginePage.Copy))
            menu.addAction("Paste", lambda: page.triggerAction(QWebEnginePage.Paste))
            menu.addAction("Select All", lambda: page.triggerAction(QWebEnginePage.SelectAll))
        menu.addSeparator()
        menu.addAction(make_text_icon('+', ICON_SIZE), "Zoom In",  self.zoom_in)
        menu.addAction(make_text_icon('−', ICON_SIZE), "Zoom Out", self.zoom_out)
        menu.addAction(make_text_icon('⛶', ICON_SIZE), "Full Screen", self.toggle_full_screen)
        menu.exec(v.mapToGlobal(pos))

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
            
    def enforce_https(url: str) -> str:
        if url.lower().startswith("http://"):
            if not (".onion" in url or "127.0.0.1" in url or "localhost" in url):
                return "https://" + url[7:]
        return url

    def search_or_load_url(self):
        text = self.search_bar.text()
        if text.startswith(('http://', 'https://')):
            self.create_new_tab(text)
        else:
            self.create_new_tab(f"https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/lite/?q={text}")

    def toggle_full_screen(self):
        is_full = not self.isFullScreen()
        self.setWindowState(self.windowState() ^ Qt.WindowFullScreen)
        QTimer.singleShot(30, lambda: self._ensure_anti_spoof_border(self.isFullScreen()))

    def toggle_javascript_via_button(self):
        # Toggle JavaScript enabled/disabled
        enabled = not self.javascript_enabled
        self.javascript_enabled = enabled
        self.settings.setValue("javascript_enabled", enabled)
        # Apply to all open tabs and reload each tab for immediate effect
        for i in range(self.tab_widget.count()):
            view = self.tab_widget.widget(i)
            if hasattr(view, "settings"):
                view.settings().setAttribute(QWebEngineSettings.JavascriptEnabled, enabled)
                # Reload the tab for JS change to take effect instantly
                view.reload()
        # Update Java icon button (always enabled/clickable)
        if hasattr(self, "java_protect_button"):
            icon_color = "#228be6" if enabled else "#22c55e"
            self.java_protect_button.setIcon(make_java_icon(icon_color))
            tip = (
                "Java Enabled (click to disable for protection)"
                if enabled else "Java Protection: Disabled (click to enable JavaScript)"
            )
            self.java_protect_button.setToolTip(tip)
        
    def new_identity_for_current_tab(self):
        view = self.current_view()
        if not view:
            return

        # Clear browser data
        self.web_profile.cookieStore().deleteAllCookies()
        self.web_profile.clearAllVisitedLinks()
        self.web_profile.clearHttpCache()
        idx = self.tab_widget.currentIndex()
        if idx in self.tab_histories:
            self.tab_histories[idx] = []

        # Ask Tor for new circuit
        newnym_sent = False
        try:
            if hasattr(self, 'controller') and self.controller:
                self.controller.signal('NEWNYM')
                newnym_sent = True
                print("[Tor] Sent NEWNYM signal for new circuit.")
            else:
                print("[Tor] No controller available for NEWNYM.")
        except Exception as ex:
            print("[Tor] NEWNYM signal failed:", ex)

        # Wait for Tor to build new circuit, then reload
        delay_ms = 2500 if newnym_sent else 0  # 2.5 seconds if NEWNYM sent, otherwise immediate
        def reload_view():
            print("[Darkelf] Reloading tab after NEWNYM delay.")
            view.reload()
        if delay_ms > 0:
            QTimer.singleShot(delay_ms, reload_view)
        else:
            reload_view()
        
    def clear_all_data(self):
        # Clear cache
        self.web_profile.clearHttpCache()
        # Clear cookies
        self.web_profile.cookieStore().deleteAllCookies()
        # Clear history (both in profile and app memory)
        self.web_profile.clearAllVisitedLinks()
        self.history_log.clear()
        # Optionally, redirect all tabs to homepage
        for i in range(self.tab_widget.count()):
            w = self.tab_widget.widget(i)
            if isinstance(w, QWebEngineView):
                w.setHtml(self.custom_homepage_html())
        QMessageBox.information(self, "Privacy", "All browsing data (cache, cookies, history) has been cleared and all tabs redirected to homepage.")
        
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

    def _searchbar_paste_and_wipe(self):
        self.search_bar.paste()
        self.wipe_clipboard_all_modes_now()

    def wipe_clipboard_all_modes_now(self):
        clipboard = QGuiApplication.clipboard()
        modes = [QClipboard.Clipboard]
        if hasattr(QClipboard, "Selection"):
            modes.append(QClipboard.Selection)
        if hasattr(QClipboard, "FindBuffer"):
            modes.append(QClipboard.FindBuffer)
        for mode in modes:
            try:
                clipboard.clear(mode=mode)
            except Exception:
                pass

    def closeEvent(self, event):
        try:
            for i in reversed(range(self.tab_widget.count())):
                w = self.tab_widget.widget(i)
                self.tab_widget.removeTab(i)
                if isinstance(w, QWebEngineView):
                    try:
                        w.setHtml(self.custom_homepage_html())
                        p = w.page()
                        if p:
                            p.setParent(None)
                            w.setPage(None)
                            p.deleteLater()
                    except RuntimeError:
                        pass
                try:
                    w.deleteLater()
                except Exception:
                    pass
        except Exception:
            pass
        print("[exit] Darkelf closing…")
        super().closeEvent(event)
    
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
            
def lockdown_builtins():
    import builtins, os
    builtins.eval = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("eval() is disabled for security"))
    builtins.exec = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("exec() is disabled for security"))
    os.system = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("os.system() is disabled for security"))
    
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
    lockdown_builtins()
    return app.exec()
    
if __name__ == "__main__":
    main()
