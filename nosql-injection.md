# NoSQL Injection

## Overview
User input is placed into a NoSQL query (MongoDB, CouchDB, etc.) without validation, letting an attacker inject query operators such as `$ne`, `$gt`, `$regex`, `$where`.
- CWE-943 | OWASP A03:2021 Injection

## Why it matters
Authentication bypass, data extraction, and in some cases server-side JavaScript execution (`$where`).

## Vulnerable patterns
```js
// Express + MongoDB: body can be {"username":"admin","password":{"$ne":null}}
db.users.findOne({ username: req.body.username, password: req.body.password });
```
```js
// $where runs JavaScript
db.users.find({ $where: "this.name == '" + name + "'" });
```
```python
# PyMongo with unvalidated JSON
users.find_one({"user": data["user"], "pass": data["pass"]})
```

## How to detect
- Query objects built directly from `req.body`, `req.query`, `request.json`.
- Use of `$where`, `mapReduce`, or `eval` with user data.
- No type check (string expected, object accepted).

## False positives
- Values are cast to string/int before use.
- Input is validated with a schema (Joi, Zod, pydantic) that rejects objects.

## Fix
- Validate type and shape of every input (must be a string/number).
- Use `mongo-sanitize` or strip keys beginning with `$` and containing `.`.
- Avoid `$where` and server-side JS.
- Hash passwords and compare in code, never in the query.

## Severity
High (auth bypass) to Critical (code execution via `$where`).
