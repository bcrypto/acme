import os
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend

def main():
    # 1. Генерируем случайный ключ
    key = os.urandom(32)  # 256-битный ключ

    # 2. Сообщение для подписи
    message = b"Test message for HMAC"

    # 3. Вычисляем HMAC
    h = hmac.HMAC(key, hashes.Provided("belt-hash", 32, 32), 
        backend=default_backend())
    h.update(message)
    signature = h.finalize()
    print("HMAC signature:", signature.hex())

    # 4. Проверяем HMAC (корректная подпись)
    verifier = hmac.HMAC(key, hashes.Provided("belt-hash", 32, 32), 
        backend=default_backend())
    verifier.update(message)
    try:
        verifier.verify(signature)
        print("Verification succeeded ✅")
    except Exception as e:
        print("Verification failed ❌:", e)

    # 5. Проверка на неверную подпись
    bad_signature = signature[:-1] + bytes([signature[-1] ^ 0xFF])
    verifier = hmac.HMAC(key,  hashes.Provided("belt-hash", 32, 32), 
        backend=default_backend())
    verifier.update(message)
    try:
        verifier.verify(bad_signature)
        print("Bad signature accepted ❌")
    except Exception:
        print("Bad signature rejected as expected ✅")

def test_hmac(hash:str, size:int, key:str, message: str) -> str:
    # Initialize a hmac context using SHA-256
    h = hmac.HMAC(bytes.fromhex(key), hashes.Provided(hash, size, 32), 
        backend=default_backend())
    h.update(bytes.fromhex(message))
    signature = h.finalize()
    return signature.hex()

def test(name:str, a:str, b:str):
    if a.upper() == b.upper():
        print(f"Test {name}: true")
    else:
        print(f"A:{a}")
        print(f"B:{b}")
        print(f"Test {name}: false")

if __name__ == "__main__":
    main()
    print("belt-hmac")
    test("В.1 - 1",test_hmac("belt-hash",32,'E9DEE72C8F0C0FA62DDB49F46F739647'
        '06075316ED247A3739CBA38303',    
        'BE32971343FC9A48A02A885F194B09A1'
        '7ECDA4D01544AF8CA58450BF66D2E88A'), 
        "D4828E6312B08BB83C9FA6535A463554"
		"9E411FD11C0D8289359A1130E930676B")
    test("В.1 - 2",test_hmac("belt-hash",32,'E9DEE72C8F0C0FA62DDB49F46F739647'
        '06075316ED247A3739CBA38303A98BF6',    
        'BE32971343FC9A48A02A885F194B09A1'
        '7ECDA4D01544AF8CA58450BF66D2E88A'), 
        "41FFE8645AEC0612E952D2CDF8DD508F"
		"3E4A1D9B53F6A1DB293B19FE76B1879F")
    test("В.1 - 3",test_hmac("belt-hash",32,'E9DEE72C8F0C0FA62DDB49F46F739647'
        '06075316ED247A3739CBA38303A98BF6'
        '92BD9B1CE5D141015445',    
        'BE32971343FC9A48A02A885F194B09A1'
        '7ECDA4D01544AF8CA58450BF66D2E88A'), 
        "7D01B84D2315C332277B3653D7EC6470"
		"7EBA7CDFF7FF70077B1DECBD68F2A144")