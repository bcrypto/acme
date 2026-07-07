import json
import sys
import os
#import datetime
import base64

from flask import Flask, jsonify, make_response, request
try:
    import bee2py
except ImportError:
    bee2py = None

app = Flask(__name__)
SAVE_DIR = None

KEYS = {}

def load_config(path):
    with open(path, "r") as f:
        return json.load(f)

def save_request(endpoint, req, resp_hdrs):
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
        jws = jws_decode(data["json"], resp_hdrs)
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
            save_request(ep, request, hdrs)
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

def jws_decode(body:dict, resp_hdrs:dict) -> dict:
    if len(body) != 3:
        return {}
    header = load_dict(body['protected'])
    payload = load_dict(body['payload'])
    jwk = header.get("jwk")
    if jwk is not None:
        KEYS[resp_hdrs["Location"]] = jwk["x"]
        print(f"Keys: {KEYS}")
        kid = resp_hdrs["Location"]
    else:
        kid = header.get("kid")
    data = body['protected'] + '.' + body['payload']
    signature = b64url_decode(body['signature'])
    valid = verify(kid, data, signature)
    return {
        "protected": header,
        "payload": payload,
        "signature": valid
    }

def verify(kid:str, data:str, signature:bytes):
    if bee2py is not None:
        pk = KEYS.get(kid)
        if pk is None:
            return False
        key = b64url_decode(pk)
        level = len(key) * 2
        pubkey = bee2py.memAlloc(128)
        bee2py.hexTo(pubkey, key.hex())
        hash = bee2py.memAlloc(64)
        der = bee2py.memAlloc(64)
        sig = bee2py.memAlloc(64+32)
        bee2py.hexTo(sig, signature.hex()) 
        params = bee2py.bign_params()
        count = bee2py.new_sizeTarr(1)
        bee2py.sizeTarr_setitem(count, 0, 64)
        value = data.encode('utf-8')
        n = len(value)
        v = bee2py.memAlloc(n)
        bee2py.hexTo(v, value.hex()) 
        if level == 128:
            bee2py.bignParamsStd(params, "1.2.112.0.2.0.34.101.45.3.1")
            bee2py.bignOidToDER(bee2py.vp2op(der), count, 
                "1.2.112.0.2.0.34.101.31.81")
            bee2py.beltHash(bee2py.vp2op(hash), v, n)
        elif level == 192:
            bee2py.bignParamsStd(params, "1.2.112.0.2.0.34.101.45.3.2")
            bee2py.bignOidToDER(bee2py.vp2op(der), count, 
                "1.2.112.0.2.0.34.101.77.12")
            bee2py.bashHash(bee2py.vp2op(hash), 192, v, n)
        elif level == 256:
            bee2py.bignParamsStd(params, "1.2.112.0.2.0.34.101.45.3.3")
            bee2py.bignOidToDER(bee2py.vp2op(der), count, 
                "1.2.112.0.2.0.34.101.77.13")
            bee2py.bashHash(bee2py.vp2op(hash), 256, v, n)
        else:
            raise ValueError("Incorrect key size")
        bee2py.memFree(v)
        c1 = bee2py.sizeTarr_getitem(count, 0)
        bee2py.delete_sizeTarr(count)
        err = bee2py.bignVerify(params, bee2py.vp2op(der), c1, 
            bee2py.vp2op(hash), bee2py.vp2op(sig), bee2py.vp2op(pubkey))
        bee2py.memFree(pubkey)
        bee2py.memFree(hash)
        bee2py.memFree(der)
        bee2py.memFree(sig)
        if err != 0:
            print(err)
        return err == 0
    else:
        return True

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python server.py <config.json>")
        sys.exit(1)

    config_path = sys.argv[1]
    config = load_config(config_path)
    register_endpoints(config)
    test_port = config.get("port", 8430)

    app.run(host="0.0.0.0", port=test_port)
