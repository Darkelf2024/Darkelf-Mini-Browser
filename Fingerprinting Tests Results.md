## Fingerprinting Test Results Explained

Darkelf Mini Browser is designed to defeat browser fingerprinting and tracking scripts. Here’s what you’ll observe when testing with popular sites:

### [Cover Your Tracks](https://coveryourtracks.eff.org/)
- **Result:** The test page will either show “test is running…” in a perpetual loop, or fail to complete.
- **Why:** Darkelf blocks key APIs (canvas, WebGL, audio, persistent storage, etc.), strips identifying headers, and randomizes screen/UA data. As a result, CoverYourTracks cannot collect enough information for a fingerprint and gets stuck in an endless test loop.

### [Am I Unique](https://amiunique.org/)
- **Result:** Most fields (especially entropy values) will display as `NaN` (Not a Number), or show generic/empty data.
- **Why:** With canvas, audio, and WebGL fingerprinting APIs disabled or randomized, and navigator/device properties spoofed, AmIUnique receives unparseable or “default” values, effectively breaking its fingerprinting calculations.

### [BrowserLeaks](https://browserleaks.com/)
- **Result:** Tests for Canvas, WebGL, Audio, Fonts, Media Devices, and Storage will be blank, spoofed, or display “undefined”/“blocked”/“null.”
- **Why:** These APIs are heavily shielded or disabled by Darkelf’s injected scripts before page JS runs. For example, Canvas returns noisy or blank images, WebGL vendor/renderer are spoofed, and persistent storage is inaccessible.

### What These Results Mean

- **“Stuck in a loop” or blank results:** The browser is successfully blocking fingerprinting vectors. Sites rely on these APIs/headers to build a unique profile; missing or spoofed data means you are not trackable by conventional browser fingerprinting.
- **NaN or generic values:** Indicates entropy has been removed and the site cannot distinguish your browser from others.
- **No persistent storage or cookies:** Your browsing cannot be correlated across sessions.
- **No unique identifiers:** No stable ID (like device IDs, canvas hashes, audio fingerprints, or plugin lists) is available for tracking.

**In short:**  
If fingerprinting/test sites cannot generate a unique browser profile or get stuck trying, Darkelf’s shields are working as intended. Your browser “looks like nothing” and cannot be uniquely identified or tracked.

---

> **Note:** No privacy tool is perfect. Sites may update their tests, and new fingerprinting techniques may appear. Always keep Darkelf updated for optimal protection.
