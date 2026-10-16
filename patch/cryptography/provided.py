from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives import _serialization

ffi = backend._ffi

lib = backend._lib


class ProviderPublicKey:
    """
    Обертка над EVP_PKEY, полученным из OpenSSL-провайдера.
    Хранит только открытый ключ, без доступа к приватному материалу.
    """

    def __init__(self, pkey_handle, handle=False):
        """
        :param pkey_handle: ffi-указатель на EVP_PKEY (EVP_PKEY *)
                           полученный из провайдера.
        """
        if pkey_handle == ffi.NULL:
            raise ValueError("EVP_PKEY handle is NULL")

        if handle:
            self._pkey = pkey_handle
        else:
            # Copy key
            dup = lib.EVP_PKEY_dup(pkey_handle)
            if dup == ffi.NULL:
                raise RuntimeError("EVP_PKEY_dup failed")
            self._pkey = dup

    def _get_md(self, md_name: str):
        """
        Возвращает EVP_MD* по имени алгоритма.
        Если md_name=None → digest не используется (Ed25519/Ed448).
        """
        if md_name is None:
            return ffi.NULL

        name_bytes = md_name.encode("ascii")
        md = lib.EVP_get_digestbyname(name_bytes)
        if md == ffi.NULL:
            raise ValueError(f"Unknown digest algorithm: {md_name}")

        return md

    def verify(self, signature: bytes, data: bytes, md: str="SHA256") -> bool:
        """
        Проверка подписи при использовании открытого ключа провайдера.
        """
        ctx = lib.EVP_MD_CTX_new()
        if ctx == ffi.NULL:
            raise RuntimeError("EVP_MD_CTX_new failed")

        try:
            # Инициализация контекста для проверки подписи
            digest = self._get_md(md)

            # pctx нам не нужен, но OpenSSL требует указатель
            pctx = ffi.new("void **")
            rc = lib.EVP_DigestVerifyInit(ctx, pctx, digest, ffi.NULL,
                self._pkey)
            if rc != 1:
                raise RuntimeError("EVP_DigestVerifyInit failed")

            sig_buf = ffi.from_buffer(signature)
            data_buf = ffi.from_buffer(data)

            rc = lib.EVP_DigestVerify(
                ctx,
                sig_buf, len(signature),
                data_buf, len(data),
            )
            return rc == 1
        finally:
            lib.EVP_MD_CTX_free(ctx)

    def get_raw_public_key(self) -> bytes:
        """
        Возвращает публичный ключ в сыром виде.
        """

        # 1. Попытка получить raw public key
        raw_len = ffi.new("size_t *")
        rc = lib.EVP_PKEY_get_raw_public_key(self._pkey, ffi.NULL, raw_len)

        if rc == 1:
            # Алгоритм поддерживает raw public key
            buf = ffi.new("unsigned char[]", raw_len[0])
            rc = lib.EVP_PKEY_get_raw_public_key(self._pkey, buf, raw_len)
            if rc != 1:
                raise RuntimeError("EVP_PKEY_get_raw_public_key failed")
            return bytes(ffi.buffer(buf, raw_len[0]))

        raise RuntimeError("Cannot extract public key from provider key")

    def __del__(self):
        # Освобождаем наш EVP_PKEY, если он ещё жив
        if hasattr(self, "_pkey") and self._pkey != ffi.NULL:
            lib.EVP_PKEY_free(self._pkey)
            self._pkey = ffi.NULL

    def public_bytes(self,
        encoding: _serialization.Encoding,
        format: _serialization.PublicFormat) -> bytes:

        """
        Exports the public key to DER or PEM format.
        """
        if format != _serialization.PublicFormat.SubjectPublicKeyInfo:
            raise ValueError(f"Unsupported format: {format}")

        if encoding == _serialization.Encoding.DER:
            return self._to_der()
        elif encoding == _serialization.Encoding.PEM:
            return self._to_pem()
        else:
            raise ValueError(f"Unsupported encoding: {encoding}")

    def _to_der(self) -> bytes:
        # i2d_PUBKEY with a NULL double pointer returns the required length
        length = lib.i2d_PUBKEY(self._pkey, ffi.NULL)
        if length <= 0:
            raise RuntimeError("Failed to calculate DER length")

        # Allocate buffer and pass pointer address to be updated by OpenSSL
        buf = ffi.new("unsigned char[]", length)
        buf_ptr = ffi.new("unsigned char**", buf)

        res = lib.i2d_PUBKEY(self._pkey, buf_ptr)
        if res <= 0:
            raise RuntimeError("Failed to serialize key to DER format")

        return bytes(ffi.buffer(buf, length))

    def _to_pem(self) -> bytes:
        bio = lib.BIO_new(lib.BIO_s_mem())
        if bio == ffi.NULL:
            raise MemoryError("Failed to allocate OpenSSL BIO")

        try:
            # Write key to memory BIO in PEM format
            if lib.PEM_write_bio_PUBKEY(bio, self._pkey) != 1:
                raise RuntimeError("Failed to write PEM to BIO")

            # Check how many bytes were written
            pending = lib.BIO_ctrl_pending(bio)
            if pending == 0:
                raise RuntimeError("BIO buffer is empty")

            # Read out of BIO into Python bytes
            buf = ffi.new("char[]", pending)
            read_bytes = lib.BIO_read(bio, buf, pending)
            if read_bytes <= 0:
                raise RuntimeError("Failed to read PEM from BIO")

            return bytes(ffi.buffer(buf, read_bytes))
        finally:
            lib.BIO_free(bio)

    @classmethod
    def from_public_bytes(cls, data: bytes, nid: int):
        """
        Создаёт публичный ключ из байтового массива.
        Поддерживает:
          - RAW public keys (Ed25519, Ed448, X25519, X448)
        """

        buf = ffi.from_buffer(data)

        # 1. Попытка загрузить RAW public key
        raw_pkey = lib.EVP_PKEY_new_raw_public_key(
            nid, ffi.NULL, buf, len(data)
        )
        if raw_pkey != ffi.NULL:
            return cls(raw_pkey, handle=True)

        # 2. Попытка загрузить DER SPKI public key
        #    Подходит для RSA, EC
        pp = ffi.new("const unsigned char **", buf)
        der_pkey = lib.d2i_PUBKEY(ffi.NULL, pp, len(data))
        if der_pkey != ffi.NULL:
            return cls(der_pkey, handle=True)

        raise ValueError("Cannot load public key from bytes")

    @classmethod
    def from_public_bytes_and_alg(cls, data: bytes, alg: str):
        """
        Создаёт публичный ключ из байтового массива.
        """
        nid = lib.OBJ_txt2nid(alg.encode("ascii"))
        print(nid)
        return cls.from_public_bytes(data, nid)


def gen_engine(alg, curve):
    algo = alg.encode("ascii")
    crv = curve.encode("ascii")
    param = b"params"

    eng_ptr = ffi.new("ENGINE **")
    ameth = lib.EVP_PKEY_asn1_find_str(eng_ptr, algo, -1)
    if ameth == ffi.NULL:
        raise RuntimeError("EVP_PKEY_asn1_find_str failed")
    nid_ptr = ffi.new("int *")
    if lib.EVP_PKEY_asn1_get0_info(nid_ptr, ffi.NULL, ffi.NULL, ffi.NULL,
        ffi.NULL, ameth) != 1:
        raise RuntimeError("EVP_PKEY_asn1_get0_info failed")
    ctx = lib.EVP_PKEY_CTX_new_id(nid_ptr[0], ffi.NULL)

    if lib.EVP_PKEY_keygen_init(ctx) != 1:
        raise RuntimeError("EVP_PKEY_keygen_init failed")
    if lib.EVP_PKEY_CTX_ctrl_str(ctx, param, crv) != 1:
        raise RuntimeError("EVP_PKEY_CTX_ctrl_str failed")

    return ctx

def gen_prov(alg, curve):
    algo = alg.encode("ascii")
    crv = curve.encode("ascii")

    ctx = lib.EVP_PKEY_CTX_new_from_name(ffi.NULL, algo, ffi.NULL)
    if ctx == ffi.NULL:
        return ffi.NULL

    if lib.EVP_PKEY_keygen_init(ctx) != 1:
            raise RuntimeError("EVP_PKEY_keygen_init failed")

    if curve is not None:
        param = lib.OSSL_PARAM_construct_utf8_string(
            b"group", crv, len(crv)
        )
        params = ffi.new("OSSL_PARAM[]", [param, lib.OSSL_PARAM_construct_end()])
        if lib.EVP_PKEY_CTX_set_params(ctx, params) != 1:
            raise RuntimeError("EVP_PKEY_CTX_set_params failed")
    return ctx


class ProviderPrivateKey:
    """
    Приватный ключ OpenSSL-провайдера.
    Ключ может быть неэкспортируемым (HSM, PKCS#11, OpenSSL provider).
    Digest-алгоритм выбирается через EVP_get_digestbyname().
    """
    def __init__(self, pkey_handle, handle=False):
        self.handle = handle
        if pkey_handle == ffi.NULL:
            raise ValueError("EVP_PKEY handle is NULL")
        self.nid = lib.EVP_PKEY_get_id(pkey_handle)
        if self.nid <= 0:
            raise RuntimeError("EVP_PKEY_get_id failed")

        self._pkey = pkey_handle

    def _get_md(self, md_name: str):
        """
        Возвращает EVP_MD* по имени алгоритма.
        Если md_name=None → digest не используется (Ed25519/Ed448).
        """
        if md_name is None:
            return ffi.NULL
        md = lib.EVP_get_digestbyname(md_name.encode("ascii"))
        if md == ffi.NULL:
            raise ValueError(f"Unknown digest algorithm: {md_name}")
        return md

    def sign(self, data: bytes, md: str = "SHA256") -> bytes:
        """
        Подпись данных через OpenSSL-провайдер.
        Digest выбирается по имени md.
        """
        ctx = lib.EVP_MD_CTX_new()
        if ctx == ffi.NULL:
            raise RuntimeError("EVP_MD_CTX_new failed")

        try:
            digest = self._get_md(md)

            pctx = ffi.new("void **")
            rc = lib.EVP_DigestSignInit(
                ctx, pctx, digest, ffi.NULL, self._pkey)
            if rc != 1:
                raise RuntimeError("EVP_DigestSignInit failed")

            data_buf = ffi.from_buffer(data)

            # Узнаём длину подписи
            siglen = ffi.new("size_t *")
            rc = lib.EVP_DigestSign(ctx, ffi.NULL, siglen, data_buf, len(data))
            if rc != 1:
                raise RuntimeError("EVP_DigestSign(size query) failed")

            sigbuf = ffi.new("unsigned char[]", siglen[0])

            rc = lib.EVP_DigestSign(ctx, sigbuf, siglen, data_buf, len(data))
            if rc != 1:
                raise RuntimeError("EVP_DigestSign failed")

            return bytes(ffi.buffer(sigbuf, siglen[0]))

        finally:
            lib.EVP_MD_CTX_free(ctx)


    def get_raw_public_key(self) -> bytes:
        """
        Возвращает публичный ключ в сыром виде.
        Для Ed25519/Ed448/X25519/X448 → raw bytes.
        Для RSA/EC → DER SubjectPublicKeyInfo.
        """

        # 1. Попытка получить raw public key (Ed25519/Ed448/X25519/X448)
        raw_len = ffi.new("size_t *")
        rc = lib.EVP_PKEY_get_raw_public_key(self._pkey, ffi.NULL, raw_len)

        if rc == 1:
            # Алгоритм поддерживает raw public key
            buf = ffi.new("unsigned char[]", raw_len[0])
            rc = lib.EVP_PKEY_get_raw_public_key(self._pkey, buf, raw_len)
            if rc != 1:
                raise RuntimeError("EVP_PKEY_get_raw_public_key failed")
            return bytes(ffi.buffer(buf, raw_len[0]))

        raise RuntimeError("Cannot extract public key from provider key")

    def get_encoded_public_key(self) -> bytes:
        """
        Возвращает публичный ключ в DER SubjectPublicKeyInfo.
        Работает для всех алгоритмов: RSA, EC, Ed25519, Ed448, X25519, X448.
        """

        # 1. Узнаём длину DER SPKI
        buf_ptr = ffi.new("unsigned char **")
        der_len = lib.i2d_PUBKEY(self._pkey, buf_ptr)
        if der_len <= 0:
            raise RuntimeError("i2d_PUBKEY failed")

        try:
            # 2. Копируем DER в Python bytes
            return bytes(ffi.buffer(buf_ptr[0], der_len))
        finally:
            lib.OPENSSL_free(buf_ptr[0])


    def public_key(self)->ProviderPublicKey:
        pk = self.get_encoded_public_key()
        return ProviderPublicKey.from_public_bytes(pk, self.nid)

    def __del__(self):
        if hasattr(self, "_pkey") and self._pkey != ffi.NULL and self.handle:
            lib.EVP_PKEY_free(self._pkey)
            self._pkey = ffi.NULL

    """
    Загружает ключи из файлового контейнера (PEM/DER/PFX)
    через OpenSSL OSSL_STORE API.
    """
    @classmethod
    def load_key(cls, filename: str):
        """
        Загружает приватный ключ из PEM или DER файла через BIO.
        """

        # 1. Читаем файл в память
        with open(filename, "rb") as f:
            data = f.read()

        # 2. Создаём BIO из буфера
        bio = lib.BIO_new_mem_buf(data, len(data))
        if bio == ffi.NULL:
            raise RuntimeError("BIO_new_mem_buf failed")

        try:
            # 3. Попытка загрузить PEM
            pkey = lib.PEM_read_bio_PrivateKey(bio, ffi.NULL, ffi.NULL,
                ffi.NULL)
            if pkey != ffi.NULL:
                return cls(pkey)

            # 4. Если PEM не подошёл — пробуем DER
            #    Для DER используем d2i_PrivateKey_bio()
            #    (OpenSSL сам определит тип ключа)
            pkey = lib.d2i_PrivateKey_bio(bio, ffi.NULL)
            if pkey != ffi.NULL:
                return cls(pkey)

        finally:
            lib.BIO_free(bio)

        raise ValueError(f"Cannot load private key from file: {filename}")

    def get_algorithm_name(self) -> str:
        """
        Возвращает имя алгоритма приватного ключа:
        RSA, EC, ED25519, ED448, X25519, X448 и т.д.
        """
        name_ptr = lib.OBJ_nid2sn(self.nid)
        if name_ptr == ffi.NULL:
            raise RuntimeError("OBJ_nid2sn failed")

        return ffi.string(name_ptr).decode("ascii")

    @classmethod
    def from_private_bytes(cls, key_bytes: bytes, algorithm: str):
        """
        Создаёт приватный ключ из байтового контейнера (PEM/DER)
        и строки алгоритма ("RSA", "EC", "ED25519", "ED448").
        """

        algo = algorithm.strip()
        nid = lib.OBJ_txt2nid(algo.encode("ascii"))

        # Попытка загрузить raw keys
        if nid != 0:
            pkey = lib.EVP_PKEY_new_raw_private_key(
                nid, ffi.NULL,
                ffi.from_buffer(key_bytes),
                len(key_bytes)
            )
            if pkey != ffi.NULL:
                return cls(pkey)

        raise ValueError(f"Cannot import private key for {algorithm}")

    @classmethod
    def generate(cls, alg, curve):
        ctx = gen_engine(alg, curve)
        if ctx == ffi.NULL:
            ctx = gen_prov(alg, curve)
        if ctx == ffi.NULL:
            raise RuntimeError(f"EVP_PKEY_CTX create failed for {alg}")
        try:
            pkey_ptr = ffi.new("EVP_PKEY **")
            if lib.EVP_PKEY_keygen(ctx, pkey_ptr) != 1:
                raise RuntimeError("EVP_PKEY_keygen failed")
            return cls(pkey_ptr[0])
        finally:
            lib.EVP_PKEY_CTX_free(ctx)


    def private_bytes(
        self,
        encoding: _serialization.Encoding,
        format: _serialization.PrivateFormat,
        encryption_algorithm: _serialization.KeySerializationEncryption,
    ) -> bytes:
        """
        Returns the key serialized as bytes.
        """
        if encoding == _serialization.Encoding.DER:
            # DER PKCS#8
            buf_ptr = ffi.new("unsigned char **")
            length = lib.i2d_PrivateKey(self._pkey, buf_ptr)
            if length <= 0:
                raise RuntimeError("i2d_PrivateKey failed")

            try:
                return bytes(ffi.buffer(buf_ptr[0], length))
            finally:
                lib.OPENSSL_free(buf_ptr[0])

        elif encoding == _serialization.Encoding.PEM:
            # PEM PKCS#8
            bio = lib.BIO_new(lib.BIO_s_mem())
            if bio == ffi.NULL:
                raise RuntimeError("BIO_new failed")

            try:
                if lib.PEM_write_bio_PrivateKey(
                    bio, self._pkey, ffi.NULL, ffi.NULL, 0, ffi.NULL, ffi.NULL
                ) != 1:
                    raise RuntimeError("PEM_write_bio_PrivateKey failed")

                mem = ffi.new("char **")
                size = lib.BIO_get_mem_data(bio, mem)
                return ffi.string(mem[0], size)

            finally:
                lib.BIO_free(bio)

        else:
            raise ValueError("Unsupported encoding")
