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
    def check_text(text):
        if not isinstance(text, str):
            raise CipherError("Для текстового шифру очікується рядок")
        return text

    @staticmethod
    def check_linear(coeffs):
        if len(coeffs) != 2:
            raise CipherError("Лінійний ключ має містити 2 коефіцієнти (A, B)")
        return Validator._check_numbers(coeffs)

    @staticmethod
    def check_nonlinear(coeffs):
        if len(coeffs) != 3:
            raise CipherError("Нелінійний ключ має містити 3 коефіцієнти (A, B, C)")
        return Validator._check_numbers(coeffs)

    @staticmethod
    def _check_numbers(coeffs):
        result = []
        for c in coeffs:
            if isinstance(c, bool) or not isinstance(c, int):
                raise CipherError("Коефіцієнти ключа повинні бути цілими числами")
            result.append(c)
        if all(c == 0 for c in result):
            raise CipherError("Коефіцієнти не можуть бути нульовими одночасно")
        return result

    @staticmethod
    def check_keyword(keyword, alphabet):
        if not isinstance(keyword, str) or not keyword.strip():
            raise CipherError("Гасло не може бути порожнім")
        index = {ch: i for i, ch in enumerate(alphabet)}
        if not any(ch.lower() in index for ch in keyword):
            raise CipherError("Гасло не містить жодної літери алфавіту")
        return keyword


# ключі шифрування: кожен клас уміє порахувати зсув для позиції p
class LinearKey:
    def __init__(self, a, b):
        self.a, self.b = Validator.check_linear((a, b))

    def shift(self, p):
        return self.a * p + self.b


class NonlinearKey:
    def __init__(self, a, b, c):
        self.a, self.b, self.c = Validator.check_nonlinear((a, b, c))

    def shift(self, p):
        return self.a * p * p + self.b * p + self.c


class KeywordKey:
    def __init__(self, keyword, alphabet):
        Validator.check_keyword(keyword, alphabet)
        index = {ch: i for i, ch in enumerate(alphabet)}
        # із гасла беремо лише літери алфавіту, їх позиції й будуть зсувами
        self.shifts = [index[ch.lower()] for ch in keyword if ch.lower() in index]

    def shift(self, p):
        return self.shifts[p % len(self.shifts)]


class TrithemiusCipher:
    def __init__(self, lang="uk"):
        if lang not in ALPHABETS:
            raise CipherError(f"Невідома мова: {lang}")
        self.lang = lang
        self.alphabet = ALPHABETS[lang]
        self.n = len(self.alphabet)
        self._index = {ch: i for i, ch in enumerate(self.alphabet)}

    def _process(self, text, key, sign):
        result = []
        p = 0  # позиція рахується лише для літер алфавіту
        for ch in text:
            pos = self._index.get(ch.lower())
            if pos is None:
                result.append(ch)
                continue
            k = key.shift(p)
            new_pos = (pos + sign * k) % self.n
            new_ch = self.alphabet[new_pos]
            result.append(new_ch.upper() if ch.isupper() else new_ch)
            p += 1
        return "".join(result)

    def encrypt(self, text, key):
        text = Validator.check_text(text)
        return self._process(text, key, 1)

    def decrypt(self, text, key):
        text = Validator.check_text(text)
        return self._process(text, key, -1)
