from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding


def load_cert(path):
    with open(path, "rb") as f:
        data = f.read()
    try:
        return x509.load_pem_x509_certificate(data, default_backend())
    except ValueError:
        return x509.load_der_x509_certificate(data, default_backend())

def check_validity(cert):
    now = datetime.now(UTC)
    if now < cert.not_valid_before_utc:
        print(f"❌ Certificate is not yet valid ({cert.not_valid_before_utc})")
        return False
    if now > cert.not_valid_after_utc:
        print(f"❌ Certificate has expired ({cert.not_valid_after_utc})")
        return False
    print("✅ Certificate validity period is OK")
    return True

def check_signature(cert, issuer_cert):
    pub = issuer_cert.public_key()
    try:
        pub.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15() if hasattr(pub, "key_size") else None,
            cert.signature_hash_algorithm,
        )
        print("✅ Certificate signature is valid")
        return True
    except Exception as e:
        print("❌ Certificate signature verification failed:", e)
        return False

def check_hostname(cert, hostname):
    try:
        cert.verify_hostname(hostname)
        print("✅ Hostname matches certificate")
        return True
    except Exception as e:
        print("❌ Hostname check failed:", e)
        return False

def main():
    # Путь к сертификату и CA
    cert = load_cert("tests/data/cert256.crt")
    issuer = load_cert("tests/data/cert.der")

    print("Subject:", cert.subject)
    print("Issuer:", cert.issuer)

    # Проверка срока действия
    check_validity(cert)

    # Проверка подписи
    check_signature(cert, issuer)

    # Проверка имени хоста
    check_hostname(cert, "example.com")

if __name__ == "__main__":
    main()
