# Contributing

Thanks for helping improve MedCrypto!

## Setup

1. Create a virtual environment and install deps:

```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -U pip
pip install -r requirements.txt
pip install -e .
```

2. Run tests:

```powershell
pytest -q
```

## Coding style

- Keep public API documented in `README.md`.
- Avoid breaking changes. If you must, add shims and deprecation warnings.
- Write minimal tests for new features.

## Security

- Do not commit secrets.
- Avoid logging raw PHI; use masking utilities.
- If you find a vulnerability, open a private issue or contact the maintainer.