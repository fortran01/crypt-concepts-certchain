# SSL Certificate Chain Validator

A Python tool for downloading, validating, and saving SSL certificate chains from domains.

## Features

- Downloads complete SSL certificate chains from domains
- Validates certificate chain integrity
- Checks certificate date validity
- Verifies basic constraints
- Saves certificate chains in PEM format
- Supports custom port specification

## Setup

- Create and activate a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

- Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Basic usage:

```bash
python get_cert.py uwaterloo.ca
```

With custom port:

```bash
python get_cert.py uwaterloo.ca --port 8443
```

## Output

The script will:

1. Fetch the certificate chain
2. Validate the certificates
3. Display validation results
4. Save the certificate chain to `certs/domain-chain.pem`

Example output:

```plain
Fetching certificate chain for uwaterloo.ca:443...

Validation Results for uwaterloo.ca:
------------------------------------------------------------
✓ Date Validity:
  Valid from 2024-01-01 00:00:00 to 2025-01-01 00:00:00
✓ Basic Constraints:
  Certificate extensions are present
✓ Chain of Trust:
  Certificate chain validates successfully
------------------------------------------------------------
Certificate chain saved to: certs/example.com-chain.pem
Number of certificates in chain: 3
```

## Requirements

- Python 3.6+
- pyOpenSSL

## Directory Structure

```plain
.
├── README.md
├── requirements.txt
├── get_cert.py
└── certs/           # Created automatically when saving certificates
    └── *.pem       # Certificate chain files
