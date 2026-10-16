from cryptography.hazmat.primitives.asymmetric.provided import ProviderPrivateKey
from cryptography.hazmat.primitives import _serialization

key = ProviderPrivateKey.generate("bign", "bign-curve256v1")

name = key.get_algorithm_name()
print(f"Name (str): {name}\n")

pubkey = key.public_key()

encKey = key.private_bytes(_serialization.Encoding.PEM, _serialization.PrivateFormat, None)
print(encKey)

