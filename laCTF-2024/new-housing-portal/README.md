<h1> New housing portal </h1>

<p> <strong> Description : </strong><i>
After that old portal, we decided to make a new one that is ultra secure and not based off any real housing sites. Can you make Samy tell you his deepest darkest secret?

Hint - You can send a link that the admin bot will visit as samy. </i> </p>

<p> So we have a web application written in javascript and an admin bot waiting for a url. The goal of the challenge is to find Samy's "secret". </p>

<p> In the web application we can : </p>
<ul>
  <li> <strong><i>/login or /register</i></strong> :Login or register :) </li>
  <li> <strong><i>/finder</i></strong> : Search a user with his username and send him an invitation link.</li>
  <li> <strong><i>/request</i></strong> : See the invitations we got.</li>
</ul>


<p> To see a user's secret, you need to receive an invitation link from the user, so we need to find a way to "force" user samy to send us an invitation link. Let's sart code review !</p>

<p> In the finder endpoint we can notice that if it finds a valid user the user information is displayed with <i>innerHTML</i> and not <i>innerText</i> !!</p>

```js
const user = await fetch('/user?q=' + encodeURIComponent(query))
  .then(r => r.json());
if ('err' in user) {
  $('.err').innerHTML = user.err;
  $('.err').classList.remove('hidden');
  return;
}
$('.user input[name=username]').value = user.username;
$('span.name').innerHTML = user.name;
$('span.username').innerHTML = user.username;
$('.user').classList.remove('hidden');
```
<p> And that user inputs such as username or name are not filtered/sanitized during registration !!</p>

```js
app.post('/register', (req, res) => {
  const username = req.body.username?.trim(); //not filtered/sanitized !!
  const password = req.body.password?.trim();
  const name = req.body.name?.trim(); //not filtered/sanitized !!
  const deepestDarkestSecret = req.body.deepestDarkestSecret?.trim();

  if (users.has(username)) {
    res.redirect('/login/?err=' + encodeURIComponent('username already exists'));
    return;
  }

  const user = {
    username,
    name,
    password,
    deepestDarkestSecret: 'todo',
    invitations: [],
    registration: Date.now()
  };
});
```

<img src=csrf-everywhere.png><img>

<p>
