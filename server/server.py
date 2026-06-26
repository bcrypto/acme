import json
import sys
import os
#import datetime
import base64

from flask import Flask, jsonify, make_response, request

app = Flask(__name__)
SAVE_DIR = None

def load_config(path):
    with open(path, "r") as f:
        return json.load(f)

def save_request(endpoint, req):
    if not SAVE_DIR:
        return
    os.makedirs(SAVE_DIR, exist_ok=True)
    timestamp = "0"    # datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")
    filename = f"{endpoint.strip('/').replace('/', '_')}_{timestamp}.json"
    filepath = os.path.join(SAVE_DIR, filename)

    data = {
        "method": req.method,
        "path": req.path,
        "headers": dict(req.headers),
        "args": req.args.to_dict(),
        "json": req.get_json(silent=True),
        "form": req.form.to_dict(),
        "data_raw": req.data.decode("utf-8", errors="ignore")
    }

    if data["headers"].get("Content-Type", "") == "application/jose+json":
        jws = jws_decode(data["json"])
        data.update(jws)

    with open(filepath, "w") as f:
        json.dump(data, f, indent=2)

def register_endpoints(config):
    global SAVE_DIR
    SAVE_DIR = config.get("save_requests_dir")

    for entry in config.get("endpoints", []):
        endpoint = entry.get("endpoint")
        method = entry.get("method", "GET").upper()
        data = entry.get("response", {})
        code = entry.get("status", 200)
        headers = entry.get("headers", {})

        def handler(response=data, status=code, hdrs=headers, ep=endpoint):
            save_request(ep, request)
            resp = make_response(jsonify(response), status)
            for k, v in hdrs.items():
                resp.headers[k] = v
            return resp

        app.add_url_rule(
            endpoint,
            endpoint,
            handler,
            methods=[method]
        )

def b64url_decode(data: str) -> bytes:
    """Декодирование base64url без паддинга."""
    # восстановить паддинг
    padding = 4 - (len(data) % 4)
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)

def load_str(s:str)->str:
    return b64url_decode(s).decode('utf-8')

def load_dict(token:str)->dict:
    s = load_str(token)
    if not s:
        return ""
    return json.loads(s)

def jws_decode(body:dict) -> dict:
    if len(body) != 3:
        return {}
    header = load_dict(body['protected'])
    payload = load_dict(body['payload'])
    #data = body['protected'] + '.' + body['payload']
    #signature = b64url_decode(body['signature'])
    return {
        "protected": header,
        "payload": payload
    }

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python server.py <config.json>")
        sys.exit(1)

    config_path = sys.argv[1]
    config = load_config(config_path)
    register_endpoints(config)
    test_port = config.get("port", 8430)

    app.run(host="0.0.0.0", port=test_port)
