import json
import base64
import sys
import os
import string

import requests
try:
    import bee2py
except ImportError:
    bee2py = None

class BignSigner:
    def __init__(self, level):
        self.level = level
        if bee2py is not None:
            self.privkey = bee2py.memAlloc(64)
            self.hash = bee2py.memAlloc(64)
            self.der = bee2py.memAlloc(64)
            self.sig = bee2py.memAlloc(64+32)
            count = bee2py.new_sizeTarr(1)
            bee2py.sizeTarr_setitem(count, 0, 64)
            self.params = bee2py.bign_params()
            if self.level == 128:
                bee2py.bignParamsStd(self.params, "1.2.112.0.2.0.34.101.45.3.1")
                bee2py.bignOidToDER(bee2py.vp2op(self.der), count, 
                    "1.2.112.0.2.0.34.101.31.81")
            elif self.level == 192:
                bee2py.bignParamsStd(self.params, "1.2.112.0.2.0.34.101.45.3.2")
                bee2py.bignOidToDER(bee2py.vp2op(self.der), count, 
                    "1.2.112.0.2.0.34.101.77.12")
            elif self.level == 256:
                bee2py.bignParamsStd(self.params, "1.2.112.0.2.0.34.101.45.3.3")
                bee2py.bignOidToDER(bee2py.vp2op(self.der), count, 
                    "1.2.112.0.2.0.34.101.77.13")
            else:
                raise ValueError("Incorrect Bign level")
            self.count = bee2py.sizeTarr_getitem(count, 0)
            bee2py.delete_sizeTarr(count)

    def setkey(self, key: bytes):
        if len(key) * 8 != self.level:
            raise ValueError("Incorrect key size")
        if bee2py is not None:
            bee2py.hexTo(self.privkey, key.hex()) 
            print(f"Private key: {key.hex()}")
            code = b64url_encode(key)
            print(f"Private key (b64): {code}")
            pubkey = bee2py.memAlloc(128)
            sbuf = "0"*1000
            bee2py.bignPubkeyCalc(bee2py.vp2op(pubkey), self.params, 
                bee2py.vp2op(self.privkey))
            sbuf = bee2py.hexFrom(sbuf, pubkey, self.level // 2)
            print(f"Public key: {sbuf}")
            pk = bytes.fromhex(sbuf)
            code = b64url_encode(pk)
            print(f"Public key (b64): {code}")

    def sign(self, value: bytes):
        if bee2py is not None:
            n = len(value)
            v = bee2py.memAlloc(n)
            bee2py.hexTo(v, value.hex()) 
            if self.level == 128:
                bee2py.beltHash(bee2py.vp2op(self.hash), v, n)
            elif self.level == 192:
                bee2py.bashHash(bee2py.vp2op(self.hash), 192, v, n)
            elif self.level == 256:
                bee2py.bashHash(bee2py.vp2op(self.hash), 256, v, n)
            err = bee2py.bignSign2(
                bee2py.vp2op(self.sig), 
                self.params, 
                bee2py.vp2op(self.der), 
                self.count, 
                bee2py.vp2op(self.hash), 
                bee2py.vp2op(self.privkey), 
                None, 0)
            bee2py.memFree(v)
            v = None
            if err != 0:
                print(err)
            sbuf = "0"*200
            sbuf = bee2py.hexFrom(sbuf, self.sig, self.level * 3 // 8)
            return bytes.fromhex(sbuf)
        else:
            return value

    def __del__(self):
        if bee2py is not None:
            bee2py.memFree(self.privkey)
            bee2py.memFree(self.hash)
            bee2py.memFree(self.der)
            bee2py.memFree(self.sig)
        
def load_config(path):
    with open(path, "r") as f:
        return json.load(f)

def load_previous(file, jsonpath):
    try:
        with open(file, "r") as f:
            data = json.load(f)
        # простая навигация вида "body.user_id"
        parts = jsonpath.split(".")
        for p in parts:
            # если есть индекс в квадратных скобках
            if "[" in p and "]" in p:
                # например "items[0]"
                field, idx_str = p.split("[", 1)
                idx = int(idx_str[:-1])  # убрать "]"
                data = data.get(field)
                if isinstance(data, list):
                    data = data[idx]
                else:
                    raise ValueError(f"Field {field} is not a list")
            else:
                data = data.get(p)
        return data
    except Exception as e:
        print(f"Failed to load {jsonpath} from {file}: {e}")
        return None

def replace_placeholders(text:str, config, outdir) -> str:
    # Parse the string and filter out the field names
    formatter = string.Formatter()
    placeholders = [name for _, name, _, _ in formatter.parse(text) 
                    if name is not None]
    replacement = {}
    for p in placeholders:
        prev_file = os.path.join(outdir, config[p]["file"])
        value = load_previous(prev_file, config[p]["jsonpath"])
        if value is not None:
            replacement[p] = value
    return text.format(**replacement)

def b64url_decode(data: str) -> bytes:
    """Декодирование base64url без паддинга."""
    # восстановить паддинг
    padding = 4 - (len(data) % 4)
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)

def b64url_encode(data: bytes) -> str:
    """Base64url без паддинга."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')

def dump_str(s:str)->str:
    return b64url_encode(s.encode('utf-8'))

def dump_dict(data:dict)->str:
    return dump_str(json.dumps(data, ensure_ascii=False))

def jws_encode(entry:dict, config:dict, outdir:str, signer:BignSigner)->dict:
    jws_header = entry.get('jws_header', {})
    header = {name: replace_placeholders(value, entry, outdir) 
            if type(value) is str else value
        for name, value in jws_header.items() }
    # print(header)
    protected = dump_dict(header)
    payload = dump_dict(entry["payload"])
    body = protected + '.' + payload
    binary = body.encode('utf-8')
    sig = signer.sign(binary)
    signature = b64url_encode(sig)
    return {
        'protected': protected,
        'payload': payload,
        'signature': signature
    }

def is_json(resp):
    return resp.headers.get("Content-Type","").startswith("application/json")

def run_tests(config, outdir, signer):
    os.makedirs(outdir, exist_ok=True)

    head = {
        "User-Agent": "AcmeTestClient/1.0"
    }

    for entry in config:
        endpoint = entry.get("endpoint")
        method = entry.get("method", "GET").upper()
        payload = entry.get("payload")
        outfile = entry.get(
            "outfile", 
            endpoint.strip("/").replace("/", "_") + ".json"
        )

        # если нужно подставить данные из прошлых ответов
        if "{" in endpoint:
            endpoint = replace_placeholders(endpoint, entry, outdir)

        url = endpoint
        print(f"Requesting {method} {url}")

        try:
            if method == "GET":
                resp = requests.get(url, headers=head, verify=False)
            elif method == "POST":
                if "jws_header" in entry:
                    head["Content-Type"] = "application/jose+json"
                    payload = jws_encode(entry, config, outdir, signer)

                resp = requests.post(url, headers=head, json=payload, 
                    verify=False)
            else:
                print(f"Unsupported method: {method}")
                continue

            data = {
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "body": resp.json() if is_json(resp) else resp.text
            }

            outpath = os.path.join(outdir, outfile)
            with open(outpath, "w") as f:
                json.dump(data, f, indent=2)

            print(f"Saved response to {outpath}")

        except Exception as e:
            print(f"Error requesting {url}: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python client.py <config.json>")
        sys.exit(1)

    config_path = sys.argv[1]

    config = load_config(config_path)
    endpoints = config.get("requests", [])
    outdir = config.get("save_answers_dir")
    pk = b64url_decode(config.get("private_key"))
    signer = BignSigner(len(pk) * 8)
    signer.setkey(pk)
    run_tests(endpoints, outdir, signer)
