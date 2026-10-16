from cryptography.hazmat.primitives.asymmetric.provided import ProviderPrivateKey

priv = bytes.fromhex("010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
key = ProviderPrivateKey.from_private_bytes(priv, "bign-curve384v1")
pubkey = key.public_key()
pub = pubkey.get_raw_public_key()
print(pub.hex())

