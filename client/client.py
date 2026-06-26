import json
import base64
import sys
import os
import string

import requests

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

def b64url_encode(data: bytes) -> str:
    """Base64url без паддинга."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')

def dump_str(s:str)->str:
    return b64url_encode(s.encode('utf-8'))

def dump_dict(data:dict)->str:
    return dump_str(json.dumps(data, ensure_ascii=False))

def jws_encode(entry:dict, config:dict, outdir:str)->dict:
    jws_header = entry.get('jws_header', {})
    header = {name: replace_placeholders(value, entry, outdir) 
        for name, value in jws_header.items() if type(value) is str }
    # print(header)
    protected = dump_dict(header)
    payload = dump_dict(entry["payload"])
    body = protected + '.' + payload
    binary = body.encode('utf-8')
    signature = b64url_encode(binary)
    return {
        'protected': protected,
        'payload': payload,
        'signature': signature
    }

def is_json(resp):
    return resp.headers.get("Content-Type","").startswith("application/json")

def run_tests(config, outdir):
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
                    payload = jws_encode(entry, config, outdir)

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
    run_tests(endpoints, outdir)
