<h1> Hacker Type : Easy </h1>

  <p> This challenge is to program a code to automatically enter words and retrieve them from the HTML page. Here's an example with python and the requests library.</p>

  ```python
  import requests

  url = "https://hacker-typer.tuctf.com/"
  s = requests.Session() # Initiate the session

  for i in range(151):
      mot = str(s.get(url).text).split('<strong name="word-title">')[1].split("</strong>")[0] # Get the word
      page = s.post(url + 'check_word', data={'word' : mot}).text
      print(page)
  ```

  <p> And we get the flag :</p>

```bash
$ python3 hackertype.py

{"next_word":"rooting","streak":1,"typing_speed":0.3976418972015381}

{"next_word":"wardialing","streak":2,"typing_speed":1.702484369277954}

...

{"next_word":"css","streak":150,"typing_speed":1.3267238140106201}

{"next_word":" ","status":"You're fast! TUCTF{SuP3R_Typ3R}","typing_speed":0}
```
