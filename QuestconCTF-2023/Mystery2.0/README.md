<h1> Mystery 2.0 </h1>

<p> This time we have a png image file </p>

<img src=another_mystery.png width=700 height=400></img>

<p> So for find the hidden scret this time we can find a another tool : <a href=https://github.com/zed-0xff/zsteg>zsteg</a>.  </p>

```
┌──(atlas㉿Kali)-[~/Documents/QuestconCTF/WU/Mystery2.0]
└─$ zsteg another_mystery.png
b1,g,lsb,xy         .. file: OpenPGP Public Key
b1,abgr,msb,xy      .. text: "}wwwwwww;"
b2,r,lsb,xy         .. text: "Y?*[*LkB"
b2,g,lsb,xy         .. text: "EAUUUUUUUU"
b2,b,msb,xy         .. text: "jUUv}VU}%c"
b2,rgba,lsb,xy      .. text: "QUESTCON{P1raT3s_Ar3_M7s!3rY}\n"
b2,abgr,msb,xy      .. text: "KKKKGOOO"
b3,rgb,lsb,xy       .. file: PGP Secret Sub-key -
b3,rgba,lsb,xy      .. file: PGP Secret Sub-key -
b4,r,msb,xy         .. text: ";3333333{"
b4,g,lsb,xy         .. text: "eDVeffffvfy"
b4,g,msb,xy         .. text: "ffffffffnfff"
b4,b,lsb,xy         .. text: "xweUgeeUwveUVx"
b4,b,msb,xy         .. text: "=33333333"
b4,rgb,lsb,xy       .. text: "bw%cEDcE"
b4,bgr,lsb,xy       .. text: "re%CdECT"
b4,rgba,lsb,xy      .. text: "%o4_Do4_"
```

<p> And we get the flag : <strong>QUESTCON{P1raT3s_Ar3_M7s!3rY} </strong> !</p>
