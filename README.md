# MedCrypto

[![CI](https://github.com/aa04l/Django-MedSecure/actions/workflows/python-package.yml/badge.svg)](https://github.com/aa04l/Django-MedSecure/actions/workflows/python-package.yml)

Repository: https://github.com/aa04l/Django-MedSecure

Advanced medical data encryption utilities with Django ORM fields. Arabic/English code comments and HIPAA-friendly audit logging.

## Features

- Strong symmetric encryption (Fernet/AES via `cryptography`)
- Per-user derived keys and per-field salts
- Rich envelope: metadata, salt, timestamp
- Django ORM encrypted fields: `EncryptedCharField`, `EncryptedTextField`, `EncryptedEmailField`, `EncryptedPhoneField`, `EncryptedIDField`, `EncryptedJSONField`
- Bulk encryption utilities and key rotation helpers
- HIPAA-friendly audit logging helpers

## Install

```powershell
pip install -U pip; pip install .
```

Or add to `pyproject.toml`/`requirements.txt` and install.

## Quick usage

```python
from medcrypto import quick_encrypt, quick_decrypt, is_encrypted

enc = quick_encrypt("Sensitive data", user_id=123)
print(enc)  # starts with MENC_
print(is_encrypted(enc))  # True
print(quick_decrypt(enc, user_id=123))  # "Sensitive data"
```

## Django model fields

```python
from django.db import models
from medcrypto import EncryptedCharField, EncryptedEmailField

class Patient(models.Model):
    name = EncryptedCharField(max_length=255)
    email = EncryptedEmailField(max_length=255)
```

Values will be transparently encrypted before save and decrypted on access in Python code.

## Environment and settings

- `MEDICAL_MASTER_KEY`: base64url key to override the derived master key.
- If not set, a key will be derived from `settings.SECRET_KEY` (if configured) or `DJANGO_SECRET_KEY` env var.

## Examples

See `examples/basic_usage.py`.

## Development

```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -U pip
pip install -e .[dev]
pip install -r requirements.txt
pytest -q
```

## Build & Publish to PyPI (optional)

```powershell
# Build sdist and wheel
python -m build

# Check the distribution
twine check dist/*

# Upload (requires a PyPI token configured)
twine upload dist/*
```

## License

MIT

## Disclaimer

This library provides building blocks for encrypting medical data. You are responsible for your application’s overall compliance with HIPAA and local regulations.

***

Arabic summary: مكتبة لتشفير بيانات طبية مع حقول Django مشفرة وتدقيق متوافق مع HIPAA.