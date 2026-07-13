# Test client ACME

Requirements:
```bash
pip install requests
```

Start:
```bash
python3 client.py config/config.json
```

Search and deactivation of account:
```bash
python3 client.py config/etc.json
```

# Test client ACME (TLS)
Requirements: path to [bee2evp](https://github.com/bcrypto/bee2evp) 
build environment is set in script `py.sh`.
Start in TLS mode:
```bash
bash ../scripts/py.sh client.py config/tlsconfig.json
```