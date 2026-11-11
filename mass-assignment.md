# Mass Assignment (Over-Posting)

## Overview
The application binds all request fields directly to a model/object, so an attacker can set fields they should not control (`isAdmin`, `role`, `balance`, `verified`).
- CWE-915 | OWASP API3:2023 Broken Object Property Level Authorization

## Vulnerable patterns
```js
// Mongoose / Sequelize
User.create(req.body);
user.update(req.body);
Object.assign(user, req.body);
```
```python
# Django
User.objects.filter(id=uid).update(**request.POST.dict())
# ModelForm / DRF serializer with fields = "__all__" on a sensitive model
```
```ruby
User.new(params[:user])   # no strong parameters
```
Attack: `POST /register {"email":"a@b.c","password":"x","role":"admin"}`

## How to detect
- Request body passed whole into create/update/assign.
- Serializers using `fields = '__all__'` or `exclude = [...]` on models with privilege fields.

## False positives
- A DTO / schema allow-list restricts accepted fields.
- Sensitive fields are read-only in the serializer.

## Fix
- Use explicit allow-lists of fields (DTOs, `permit(...)`, `fields = ["name","email"]`).
- Mark privilege fields read-only; set them only server-side.
- Separate input models from database models.

## Severity
High (privilege escalation) to Critical (admin takeover).
