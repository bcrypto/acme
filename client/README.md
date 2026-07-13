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
Start in TLS mode:
```bash
bash ../scripts/py.sh client.py config/tlsconfig.json
```