# Python CodeQL Fresh Test Repository

This repository contains a vulnerable Python Flask application designed to test CodeQL's optimized configuration.

## Vulnerabilities Included

1. **SQL Injection** - `/users` endpoint
2. **Command Injection** - `/ping` endpoint  
3. **Path Traversal** - `/view` endpoint
4. **Reflected XSS** - `/search` endpoint
5. **Hardcoded Credentials** - `/secret` endpoint
6. **Insecure Deserialization** - `/deserialize` endpoint
7. **Weak Cryptography (MD5)** - `/hash` endpoint
8. **File Upload Vulnerability** - `/upload` endpoint
9. **Debug Mode Enabled** - Flask app runs in debug mode

## CodeQL Testing

This repository is configured with an optimized CodeQL setup that should:
- Detect all real security vulnerabilities
- Filter out false positives (unused imports, unused variables)
- Provide high-precision results

## Running the Application

```bash
pip install -r requirements.txt
python app.py
```

## CodeQL Analysis

Run the "Optimized CodeQL Analysis" workflow from the Actions tab to test the configuration.
