# Test server ACME

Requirements:
```bash
pip install flask
```

Start:
```bash
python3 server.py config/config.json
```

Search and deactivation of account:
```bash
python3 server.py config/etc.json
```

# Test server ACME (TLS)
Deploy:
```console
$ docker compose build
$ docker-compose up -d tls256
```

Open 2 terminals.

In the first:
```bash
docker exec -it tls256 bash
nginx -g "daemon off;" 
```

In the second:
```bash
docker exec -it flask bash
python3 /acme/server.py /acme/config/tlsconfig.json
```

Finish after closing terminals:
```bash
docker compose down
```