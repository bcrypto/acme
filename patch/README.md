# Patches for Python libraries

Activate custom Python virtual environment before patched library installation:
```
python3 -m venv env
. env/bin/activate
```
Prerequisites:
```
echo "BEE2EVP_PATH=../path/to/bee2evp" > .env
```

## Cryptography
Patch for git diff and a file to copy are in the folder `cryptography`.
OpenSSL installation with options `no-shared no-ssl2 no-ssl3 -fPIC` should
be used for build.

Run build script with options for setup+patch `-s` and build+install '-b':
```
bash scripts/build.sh -s -b
```
