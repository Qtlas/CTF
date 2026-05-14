<h1> Inspector Gadget </h1>

<p>To recover the flag we can use the Inspect tool or <a href=https://curl.se/>cURL</a> to find the 4 parts of the flag.</br>
First we find the 3rd part of the flag with a simple analysis of the HTML code. </p>

```bash
$ curl https://inspector-gadget.chal.nbctf.com/
        ...

        function getflag(){
            window.location.href="supersecrettopsecret.txt"
        }

        ...

        <img src="Krooter Gadget.jpg" alt="Flag Part 3/4: D3tect1v3_">

        ...
</html>
```

<p> In  the same HTML code we notice a particular function getflag() which redirects us to a text file name 'supersecrettopsecret.txt', which brings us to the second part of the flag.</p>

```bash
$ curl https://inspector-gadget.chal.nbctf.com/supersecrettopsecret.txt
Flag Part 2/4:
J06_
```
<p> Back to the main page, after reviewing all the links we find the first part of the flag in the header of the page /gadgetmag.html </p>


```bash
$ curl https://inspector-gadget.chal.nbctf.com/gadgetmag.html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Flag Part 1/4:nbctf{G00d_</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Roboto&display=swap" rel="stylesheet">
</head>
```

<p> For the last part we cannot find it by browsing through the HTTP links, you have to look at /robots.txt and go to /mysecretfiles.html </p>

```
$ curl https://inspector-gadget.chal.nbctf.com/robots.txt    
User-agent: *
Disallow: /mysecretfiles.html
```

```
$ curl https://inspector-gadget.chal.nbctf.com/mysecretfiles.html                                                  
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
</head>
<body>
    <h1>You found my secret page!</h1>
    <p>Here's part of the flag for your troubles, part 4/4 G4dg3t352}</p>
</body>
</html>%
```

<p> Now we just have to put the parts end to end to obtain a valid flag : <strong>nbctf{G00d_J06_D3tect1v3_G4dg3t352}</strong>
</p>             
