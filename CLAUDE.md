# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Flask backend server for decoding Secure Unique NFC Message (SUN) from NTAG 424 DNA and NTAG 424 DNA TagTamper NFC tags. It implements cryptographic validation according to NXP's AN12196 specification for NTAG 424 DNA features.

## Development Commands

### Setup and Running
```bash
# Setup virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies and setup config
pip3 install -r requirements.txt
cp config.dist.py config.py

# Run development server
python3 app.py --host 0.0.0.0 --port 5000
```

### Testing
```bash
# Install test dependencies first
pip install pytest

# Run all tests
pytest

# Run specific test file
pytest tests/test_libsdm.py
```

### Code Quality
```bash
# Lint with flake8 (same as CI)
flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics
flake8 . --count --exit-zero --max-complexity=10 --max-line-length=127 --statistics

# Format/lint with ruff (configured in ruff.toml)
ruff check .
```

## Architecture

### Core Components

**app.py** - Main Flask application with endpoints:
- `/` - Main page with examples
- `/tag`, `/tagtt` - SUN message decryption (HTML/JSON responses)
- `/tagpt` - Plain text validation
- `/api/tag`, `/api/tagtt`, `/api/tagpt` - JSON API endpoints
- `/webnfc` - WebNFC demo page

**libsdm/** - Core cryptographic library:
- `sdm.py` - Main SUN message decryption/validation logic
- `derive.py` - Standard key derivation (current method)
- `legacy_derive.py` - Legacy key derivation (pre-2023)
- `lrp.py` - LRP (Leakage Resilient Primitive) implementation

**config.py** - Configuration (copy from config.dist.py):
- `MASTER_KEY` - 16-byte master key for tag authentication
- `DERIVE_MODE` - "standard" or "legacy" key derivation
- `REQUIRE_LRP` - Enforce LRP encryption mode vs AES

### Key Derivation Modes

The system supports two key derivation modes controlled by `DERIVE_MODE`:
- `"standard"` - Current method (post-2023), uses `derive.py`
- `"legacy"` - Pre-2023 method, uses `legacy_derive.py`

### Encryption Modes

Supports both AES and LRP encryption modes for NTAG 424 DNA tags. LRP mode can be enforced via `REQUIRE_LRP=True` in config.

### Tag Tamper Detection

TagTamper variants (`/tagtt` endpoints) decode tamper status from file data:
- 'C','C' = secure (not tampered)
- 'O','C' = tampered (loop closed)
- 'O','O' = tampered (loop open)
- 'I','I' = not initialized
- 'N','T' = not supported

## Docker Usage

```bash
# Run with Docker
docker run -p 5000:80 -e MASTER_KEY=00000000000000000000000000000000 icedevml/sdm-backend:latest
```

## Security Notes

- Demo mode uses all-zeros master key (`MASTER_KEY = b"\x00" * 16`)
- Production should use unique 16-byte master key (hex encoded)
- All cryptographic operations follow NXP AN12196 specification