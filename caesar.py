UKRAINIAN = "абвгґдеєжзиіїйклмнопрстуфхцчшщьюя"
ENGLISH = "abcdefghijklmnopqrstuvwxyz"

ALPHABETS = {
    "uk": UKRAINIAN,
    "en": ENGLISH,
}


class CipherError(Exception):
    pass


class Validator:
    @staticmethod
    def check_key(key, modulo):
        if isinstance(key, bool) or not isinstance(key, int):
            raise CipherError("Ключ повинен бути цілим числом")
        key %= modulo
        if key == 0:
            raise CipherError("Ключ не може дорівнювати 0")
        return key

    @staticmethod
    def check_text(text):
        if not isinstance(text, str):
            raise CipherError("Для текстового шифру очікується рядок")
        return text

    @staticmethod
    def check_bytes(data):
        if not isinstance(data, (bytes, bytearray)):
            raise CipherError("Для бінарного шифру очікуються байти")
        return bytes(data)


class CaesarCipher:
    def __init__(self, lang="uk"):
        if lang not in ALPHABETS:
            raise CipherError(f"Невідома мова: {lang}")
        self.lang = lang
        self.alphabet = ALPHABETS[lang]
        self.n = len(self.alphabet)
        self._index = {ch: i for i, ch in enumerate(self.alphabet)}

    def _shift_char(self, ch, k):
        pos = self._index.get(ch.lower())
        if pos is None:
            return ch  # цифри, пробіли, розділові знаки не чіпаємо
        shifted = self.alphabet[(pos + k) % self.n]
        return shifted.upper() if ch.isupper() else shifted

    def encrypt(self, text, key):
        text = Validator.check_text(text)
        k = Validator.check_key(key, self.n)
        return "".join(self._shift_char(ch, k) for ch in text)

    def decrypt(self, text, key):
        text = Validator.check_text(text)
        k = Validator.check_key(key, self.n)
        return "".join(self._shift_char(ch, -k) for ch in text)


# шифрування довільних файлів побайтово
class ByteCaesarCipher:
    N = 256

    def encrypt(self, data, key):
        data = Validator.check_bytes(data)
        k = Validator.check_key(key, self.N)
        return bytes((b + k) % self.N for b in data)

    def decrypt(self, data, key):
        data = Validator.check_bytes(data)
        k = Validator.check_key(key, self.N)
        return bytes((b - k) % self.N for b in data)
