import base64
from math import gcd, lcm

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


class RSAError(Exception):
    pass


class RSACipher:
    """Асиметричне шифрування RSA з генерацією пари ключів через pycryptodome."""

    def __init__(self):
        self._key = None  # повна пара (з закритим ключем)

    def generate_keys(self, bits=2048):
        if bits < 1024:
            raise RSAError("Довжина ключа має бути не меншою за 1024 біти")
        self._key = RSA.generate(bits)
        return self.export_public(), self.export_private()

    def export_public(self):
        if self._key is None:
            raise RSAError("Ключі ще не згенеровано")
        return self._key.publickey().export_key().decode("ascii")

    def export_private(self):
        if self._key is None:
            raise RSAError("Ключі ще не згенеровано")
        return self._key.export_key().decode("ascii")

    def encrypt(self, text, public_pem):
        try:
            pub = RSA.import_key(public_pem)
        except (ValueError, IndexError, TypeError):
            raise RSAError("Некоректний відкритий ключ")
        cipher = PKCS1_OAEP.new(pub)
        data = text.encode("utf-8")
        if len(data) > pub.size_in_bytes() - 42:
            raise RSAError("Повідомлення задовге для цього розміру ключа")
        return base64.b64encode(cipher.encrypt(data)).decode("ascii")

    def decrypt(self, b64, private_pem):
        try:
            priv = RSA.import_key(private_pem)
        except (ValueError, IndexError, TypeError):
            raise RSAError("Некоректний закритий ключ")
        if not priv.has_private():
            raise RSAError("Для розшифрування потрібен закритий ключ")
        try:
            raw = base64.b64decode(b64)
        except (ValueError, TypeError):
            raise RSAError("Шифрограма не є коректним base64")
        cipher = PKCS1_OAEP.new(priv)
        try:
            return cipher.decrypt(raw).decode("utf-8", errors="replace")
        except ValueError:
            raise RSAError("Не вдалося розшифрувати: невірний ключ або дані")


def modinv(a, m):
    # розширений алгоритм Евкліда
    g, x = _egcd(a, m)
    if g != 1:
        raise RSAError("Оберненого елемента не існує (e не взаємно просте з φ)")
    return x % m


def _egcd(a, b):
    old_r, r = a, b
    old_s, s = 1, 0
    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
    return old_r, old_s


class TextbookRSA:
    """Навчальний RSA на малих числах - для перевірки на чисельному прикладі."""

    def __init__(self, p, q, e=None):
        if not (_is_prime(p) and _is_prime(q)):
            raise RSAError("p і q мають бути простими числами")
        if p == q:
            raise RSAError("p і q мають бути різними")
        self.p, self.q = p, q
        self.n = p * q
        self.phi = (p - 1) * (q - 1)
        # функція Кармайкла - за нею обчислюється закритий показник у сучасному RSA
        self.lam = lcm(p - 1, q - 1)
        self.e = e if e is not None else self._pick_e()
        if gcd(self.e, self.lam) != 1:
            raise RSAError("e має бути взаємно простим з λ(n)")
        self.d = modinv(self.e, self.lam)

    def _pick_e(self):
        for cand in (65537, 17, 7, 5, 3):
            if cand < self.lam and gcd(cand, self.lam) == 1:
                return cand
        e = 3
        while gcd(e, self.lam) != 1:
            e += 2
        return e

    def encrypt_num(self, m):
        if m >= self.n:
            raise RSAError(f"Повідомлення m має бути меншим за n={self.n}")
        return pow(m, self.e, self.n)

    def decrypt_num(self, c):
        return pow(c, self.d, self.n)

    @property
    def public_key(self):
        return (self.e, self.n)

    @property
    def private_key(self):
        return (self.d, self.n)


def _is_prime(num):
    if num < 2:
        return False
    i = 2
    while i * i <= num:
        if num % i == 0:
            return False
        i += 1
    return True
