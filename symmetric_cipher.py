import base64

from Crypto.Cipher import DES, DES3, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


class CipherError(Exception):
    pass


# опис підтримуваних алгоритмів: модуль, розмір блоку та допустимі довжини ключа
ALGORITHMS = {
    "DES": {"module": DES, "block": 8, "key_sizes": (8,)},
    "TripleDES": {"module": DES3, "block": 8, "key_sizes": (16, 24)},
    "AES": {"module": AES, "block": 16, "key_sizes": (16, 24, 32)},
}

# режими зчеплення; ECB не використовує вектор ініціалізації
MODES = {
    "ECB": {"needs_iv": False},
    "CBC": {"needs_iv": True},
    "CFB": {"needs_iv": True},
    "OFB": {"needs_iv": True},
}


class SymmetricCipher:
    """Симетричне блокове шифрування з динамічним вибором алгоритму і режиму."""

    def __init__(self, algorithm="DES", mode="CBC"):
        if algorithm not in ALGORITHMS:
            raise CipherError(f"Невідомий алгоритм: {algorithm}")
        if mode not in MODES:
            raise CipherError(f"Невідомий режим: {mode}")
        self.algorithm = algorithm
        self.mode = mode
        self.spec = ALGORITHMS[algorithm]

    @property
    def block_size(self):
        return self.spec["block"]

    @property
    def needs_iv(self):
        return MODES[self.mode]["needs_iv"]

    def generate_key(self):
        size = self.spec["key_sizes"][0]
        if self.algorithm == "TripleDES":
            # DES3 вимагає ключ без збігу половин
            return DES3.adjust_key_parity(get_random_bytes(size))
        return get_random_bytes(size)

    def generate_iv(self):
        return get_random_bytes(self.block_size)

    def _check_key(self, key):
        if len(key) not in self.spec["key_sizes"]:
            allowed = " або ".join(str(s) for s in self.spec["key_sizes"])
            raise CipherError(f"{self.algorithm}: довжина ключа має бути {allowed} байт")

    def _check_iv(self, iv):
        if self.needs_iv:
            if not iv or len(iv) != self.block_size:
                raise CipherError(f"Вектор ініціалізації має містити {self.block_size} байт")

    def _new_cipher(self, key, iv):
        module = self.spec["module"]
        mode_const = getattr(module, f"MODE_{self.mode}")
        if self.needs_iv:
            return module.new(key, mode_const, iv=iv)
        return module.new(key, mode_const)

    def encrypt(self, data, key, iv=None):
        if isinstance(data, str):
            data = data.encode("utf-8")
        self._check_key(key)
        self._check_iv(iv)
        cipher = self._new_cipher(key, iv)
        # для CFB/OFB довжина не має бути кратною блоку, для ECB/CBC - вирівнюємо
        if self.mode in ("ECB", "CBC"):
            data = pad(data, self.block_size)
        return cipher.encrypt(data)

    def decrypt(self, data, key, iv=None):
        self._check_key(key)
        self._check_iv(iv)
        cipher = self._new_cipher(key, iv)
        plain = cipher.decrypt(data)
        if self.mode in ("ECB", "CBC"):
            try:
                plain = unpad(plain, self.block_size)
            except ValueError:
                raise CipherError("Не вдалося розшифрувати: невірний ключ або дані")
        return plain

    def encrypt_text(self, text, key, iv=None):
        return base64.b64encode(self.encrypt(text, key, iv)).decode("ascii")

    def decrypt_text(self, b64, key, iv=None):
        try:
            raw = base64.b64decode(b64)
        except (ValueError, TypeError):
            raise CipherError("Шифрограма не є коректним base64")
        return self.decrypt(raw, key, iv).decode("utf-8", errors="replace")
