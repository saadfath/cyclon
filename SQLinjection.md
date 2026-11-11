---
id: sql-injection
title: SQL Injection
cwe: CWE-89
owasp: A03 Injection
severity: high
languages: [python, javascript, php, java]
scanner_rules: [sql-injection, string-concat-in-query, raw-sql-with-user-input]
---

## What it is
SQL injection (SQLi) happens when user input is placed inside a SQL query without protection. The attacker writes input that changes the meaning of the query, so the database runs commands the developer never planned.

## How it happens
The code builds the query as a string (concatenation, f-strings, `.format()`, `%` formatting, template literals). The database receives one text and cannot know which part is the developer's SQL and which part is the user's data, so it runs all of it as SQL.

## Types of SQL injection
- **In-band (classic):** the attacker sees the result directly in the response. Example: `1 OR 1=1` returns all rows.
- **Union-based:** the attacker uses `UNION SELECT` to add data from other tables to the response.
- **Blind (boolean or time-based):** the page shows no data, but the attacker learns information from true/false behavior or from response delays.
- **Second-order:** the malicious input is saved safely first, then used unsafely in a later query.

## Vulnerable example
### Python
```python
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
```
```python
query = f"SELECT * FROM users WHERE name = '{name}'"
cursor.execute(query)
```

### JavaScript (Node.js)
```javascript
const query = `SELECT * FROM users WHERE id = ${req.params.id}`;
db.query(query);
```

### PHP
```php
$result = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_GET['id']);
```

### Java
```java
String query = "SELECT * FROM users WHERE id = " + request.getParameter("id");
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery(query);
```

If `id` is `1 OR 1=1`, every user is returned. If `id` is `1; DROP TABLE users`, some database drivers may run the second command too.

## Safe example
### Python
```python
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = %s"
    cursor.execute(query, (user_id,))
```

### JavaScript (Node.js)
```javascript
db.query("SELECT * FROM users WHERE id = ?", [req.params.id]);
```

### PHP
```php
$stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("i", $_GET['id']);
$stmt->execute();
```

### Java
```java
PreparedStatement stmt = connection.prepareStatement("SELECT * FROM users WHERE id = ?");
stmt.setInt(1, Integer.parseInt(request.getParameter("id")));
ResultSet rs = stmt.executeQuery();
```
In every case the query and the values are sent separately (parameterized query), so the input is always treated as data and never as SQL.

## How to detect it
- A string with `SELECT`, `INSERT`, `UPDATE`, or `DELETE` that is joined with a variable using `+`, an f-string, `.format()`, `%`, or a template literal.
- That string is passed to `execute()`, `query()`, `executeQuery()`, `mysqli_query()`, or a raw query function of an ORM.
- The variable comes from user input: request parameters, form fields, headers, cookies, uploaded files, or data read from the database that was saved from user input (second-order).
- ORM raw queries (`raw()`, `execute()`, `text()`, `sequelize.query()`) that build the SQL string with variables.
- Dynamic parts that placeholders cannot protect, such as table names, column names, or `ORDER BY` direction taken from the user.

## Impact
- Reading private data: users, emails, password hashes, tokens.
- Bypassing login (for example with `' OR '1'='1`).
- Changing or deleting data.
- In some setups, reading files or running commands on the database server.
- Full database takeover when the database user has high permissions.

## How to fix it
1. Use parameterized queries (prepared statements) with placeholders (`?`, `%s`, `$1`) and pass values separately.
2. Prefer an ORM's normal query methods and avoid raw SQL. If raw SQL is needed, still use its parameter binding.
3. Placeholders cannot be used for table names, column names, or sort direction. For these, check the user's value against a fixed allow-list in the code.
4. Never build SQL by joining strings, even when the input looks safe.
5. Give the database user only the permissions the application needs (least privilege).
6. Do not show raw database errors to users.
7. Input validation (type, length, format) is a useful extra layer, but it does not replace parameterized queries.

## False positives
- The joined value is a hardcoded constant, not user input (for example a fixed table name defined in the code).
- The value was checked against a fixed allow-list before use (for example only `"asc"` or `"desc"`).
- The value is a number converted with a strict type conversion before use (for example `int(user_id)`), although parameterized queries are still better.
- The scanner flags a query in test or example code that never runs with real input.
- The query uses an ORM method that already binds parameters safely.

## Confidence guide
- **High:** user input reaches the query through concatenation, an f-string, or a template literal, and no parameterization or allow-list is used.
- **Medium:** the query is built dynamically but it is not clear where the value comes from, or there is a conversion that may or may not be enough.
- **Low:** the value looks like a constant, comes from a trusted internal source, or is checked against an allow-list.
