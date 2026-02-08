<h1> Web Explorer's Journey </h1>

<p> This is a web-challenge with a basic encrypt flag.<p>

```
let flag = "flag{Test_Flag}";
let encryptedFlag = "";
function encodeFlag() {
  for (let i = 0; i < flag.length; i++) {
    encryptedFlag += flag.charCodeAt(i);
  }
}

encodeFlag();
document.getElementById("flag").innerHTML = encryptedFlag;
```

`
encryptedFlag = 81856983846779781238751669551888076488251829549839552875183487751125
`

<p> To decrypt the encryptedFlag we use the fonction String.formCharCode</p>


```
console.log(String.fromCharCode(81, 85, 69, 83, 84, 67, 79, 78, 123, 87, 51, 66, 95, 51, 88, 80, 76, 48, 82, 51, 82, 95, 49, 83, 95, 52, 87, 51, 83, 48, 77, 51, 125));

> QUESTCON{W3B_3XPL0R3R_1S_4W3S0M3}
```

<p> And we get the flag : <strong>QUESTCON{W3B_3XPL0R3R_1S_4W3S0M3} </strong></p>
