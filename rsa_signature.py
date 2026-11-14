import base64
import binascii

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA1, SHA256, SHA512


class SignatureError(Exception):
    pass


# підтримувані алгоритми гешування повідомлення
HASHES = {
    "SHA-1": SHA1,
    "SHA-256": SHA256,
    "SHA-512": SHA512,
}


class RSASigner:
    """Формування та перевірка електронного цифрового підпису на основі RSA."""

    def __init__(self, hash_name="SHA-256"):
        if hash_name not in HASHES:
            raise SignatureError(f"Невідомий алгоритм гешування: {hash_name}")
        self.hash_name = hash_name
        self._key = None

    def generate_keys(self, bits=2048):
        if bits < 1024:
            raise SignatureError("Довжина ключа має бути не меншою за 1024 біти")
        self._key = RSA.generate(bits)
        return self.export_public(), self.export_private()

    def export_public(self):
        if self._key is None:
            raise SignatureError("Ключі ще не згенеровано")
        return self._key.publickey().export_key().decode("ascii")

    def export_private(self):
        if self._key is None:
            raise SignatureError("Ключі ще не згенеровано")
        return self._key.export_key().decode("ascii")

    def _digest(self, text):
        return HASHES[self.hash_name].new(text.encode("utf-8"))

    def hash_hex(self, text):
        return self._digest(text).hexdigest()

    def sign(self, text, private_pem):
        try:
            priv = RSA.import_key(private_pem)
        except (ValueError, IndexError, TypeError):
            raise SignatureError("Некоректний закритий ключ")
        if not priv.has_private():
            raise SignatureError("Для підпису потрібен закритий ключ")
        digest = self._digest(text)
        signature = pkcs1_15.new(priv).sign(digest)
        return base64.b64encode(signature).decode("ascii")

    def verify(self, text, signature_b64, public_pem):
        try:
            pub = RSA.import_key(public_pem)
        except (ValueError, IndexError, TypeError):
            raise SignatureError("Некоректний відкритий ключ")
        try:
            signature = base64.b64decode(signature_b64)
        except (ValueError, TypeError, binascii.Error):
            return False
        digest = self._digest(text)
        try:
            pkcs1_15.new(pub).verify(digest, signature)
            return True
        except (ValueError, TypeError):
            return False
