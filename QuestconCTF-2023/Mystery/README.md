<h1> Mystery </h1>

<p> This challenge is to find a <i>"hidden treasure"</i> in a JPEG file image. For steganography challenges we can find some useful tools at this link : <a href=https://k-lfa.info/tools-stegano/>Steganography tools</a>, and in the description of the challenge we have this hint <i>"Can you discover the hidden treasure without a password ?"</i>.</p>

<img src=pirate.jpg width=700 height=400 style="display: block; margin: 0 auto"></img>

<p> With this informations we try to extract hidden information with <a href=https://www.kali.org/tools/steghide/>steghide</a> : </p>

```
──(atlas㉿Kali)-[~/Documents/QuestconCTF/WU/Mystery]
└─$ steghide extract -sf pirate.jpg
Entrez la passphrase:
Écriture des données extraites dans "mystery".

┌──(atlas㉿Kali)-[~/Documents/QuestconCTF/WU/Mystery]
└─$ exiftool mystery
ExifTool Version Number         : 12.57
File Name                       : mystery
Directory                       : .
File Size                       : 17 kB
File Modification Date/Time     : 2023:10:30 04:24:38+00:00
File Access Date/Time           : 2023:10:30 04:25:05+00:00
File Inode Change Date/Time     : 2023:10:30 04:24:38+00:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : None
X Resolution                    : 1
Y Resolution                    : 1
Exif Byte Order                 : Big-endian (Motorola, MM)
Processing Software             : Hacker
Make                            : Alert
Camera Model Name               : Alert
Exif Version                    : 0230
Components Configuration        : Y, Cb, Cr, -
Flashpix Version                : 0100
Image Unique ID                 : UVVFU1RDT057TXk1dDNyeV8xc180dzNzMG1lIX0=
Image Width                     : 360
Image Height                    : 360
Encoding Process                : Progressive DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 1
Image Size                      : 360x360
Megapixels                      : 0.130
```

<p>And we find a another JPEG file image with a base64 encode Image Unique ID. And when we decode : </p>

```
┌──(atlas㉿Kali)-[~/Documents/QuestconCTF/WU/Mystery]
└─$ echo -n "UVVFU1RDT057TXk1dDNyeV8xc180dzNzMG1lIX0=" | base64 --decode
QUESTCON{My5t3ry_1s_4w3s0me!}
```

<p> We find the flag ! </p>
