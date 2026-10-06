from trithemius import TrithemiusCipher, ALPHABETS, CipherError


class KnownPlaintextAttack:
    """Відновлення ключа Тритеміуса за парою «відкритий - зашифрований текст»."""

    def __init__(self, lang="uk"):
        if lang not in ALPHABETS:
            raise CipherError(f"Невідома мова: {lang}")
        self.lang = lang
        self.alphabet = ALPHABETS[lang]
        self.n = len(self.alphabet)
        self._index = {ch: i for i, ch in enumerate(self.alphabet)}

    def _recover_shifts(self, plain, cipher):
        if len(plain) != len(cipher):
            raise CipherError("Довжини текстів не збігаються")
        shifts = []
        for a, b in zip(plain, cipher):
            pa = self._index.get(a.lower())
            pb = self._index.get(b.lower())
            if pa is None and pb is None:
                continue
            if pa is None or pb is None:
                raise CipherError("Тексти не відповідають один одному")
            shifts.append((pb - pa) % self.n)
        if not shifts:
            raise CipherError("Недостатньо даних для атаки")
        return shifts

    def recover_linear(self, plain, cipher):
        shifts = self._recover_shifts(plain, cipher)
        if len(shifts) < 2:
            raise CipherError("Для лінійного ключа потрібно щонайменше 2 символи")
        # при p=0 маємо B, різниця сусідніх зсувів дає A
        b = shifts[0] % self.n
        a = (shifts[1] - shifts[0]) % self.n
        if not self._matches(shifts, lambda p: a * p + b):
            raise CipherError("Не вдалося відновити лінійний ключ")
        return a, b

    def recover_nonlinear(self, plain, cipher):
        shifts = self._recover_shifts(plain, cipher)
        if len(shifts) < 3:
            raise CipherError("Для нелінійного ключа потрібно щонайменше 3 символи")
        c = shifts[0] % self.n
        # розв'язуємо систему для p = 0, 1, 2
        s1 = (shifts[1] - c) % self.n   # A + B
        s2 = (shifts[2] - c) % self.n   # 4A + 2B
        for a in range(self.n):
            b = (s1 - a) % self.n
            if (4 * a + 2 * b) % self.n == s2:
                if self._matches(shifts, lambda p: a * p * p + b * p + c):
                    return a, b, c
        raise CipherError("Не вдалося відновити нелінійний ключ")

    def recover_keyword_shifts(self, plain, cipher):
        # повертає послідовність зсувів гасла (саме гасло однозначно не відновлюється)
        return self._recover_shifts(plain, cipher)

    def _matches(self, shifts, func):
        return all(func(p) % self.n == s for p, s in enumerate(shifts))
