import base64

from cryptography.hazmat.primitives.asymmetric.provided import ProviderPrivateKey

# 1. Load private key
private_key = ProviderPrivateKey.load_key("tests/data/priv256.key")
name = private_key.get_algorithm_name()
print(f"Name (str): {name}\n")

# Extract the corresponding public key
pk = private_key.get_raw_public_key()
print(f"Public key (hex): {pk.hex()}\n")

pk = base64.b64encode(private_key.get_encoded_public_key())
print(f"Public key (b64): {pk.decode('ascii')}\n")

# 2. Define the message (must be bytes)
message = b"This is a confidential and authentic message."

# 3. Sign the message
signature = private_key.sign(message, md="belt-hash")
print(f"Signature (hex): {signature.hex()}\n")

#with open("signature.bin", "wb") as file:
#    file.write(signature)

# 4. Verify the signature
try:
    public_key = private_key.public_key()
    public_key.verify(signature, message, 'belt-hash')
    print("Verification Successful: The signature is authentic and the message is intact.")
except Exception as e:
    print(f"Verification Failed: {e}")
