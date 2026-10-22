import random

from book_cipher import CipherError


# уривок тексту-ключа для пословного шифру
DEFAULT_BOOK = (
    "Антон був розумний аналітик. Багато бачив, береже брата. "
    "Вечорами він вивчав важливі відомості. Григорій готував гарну "
    "доповідь довго. Його ереміти його еталон. Жодного жалю. "
    "Зранку зібрались звичні знайомі. Іваніноді ішов інакше. "
    "Київ красивий край. Лагідний літній луг. Мама мила мед. "
    "Над нами небо. Осінь очікує одразу. Під покровом природи. "
    "Річка радує рибу. Сонце світить спокійно. Тиша таємнича. "
    "Увечері усі умілі. Філософ фіксує факти. Хмари химерні. "
    "Цікаво цінувати час. Чесно чекати чуда. Шепіт шовкових шат. "
    "Щире щастя щодня. Юні юнаки. Яскраве явище."
)


class WordBookCipher:
    """Пословний книжковий шифр.

    Кожне слово відкритого тексту замінюється номером слова у тексті-ключі,
    яке починається на ту саму букву. Якщо таких слів кілька, вибір випадковий.
    """

    def __init__(self, book=DEFAULT_BOOK):
        if not isinstance(book, str) or not book.strip():
            raise CipherError("Текст-ключ не може бути порожнім")
        self.words = self._tokenize(book)
        if not self.words:
            raise CipherError("У тексті-ключі немає слів")
        # перша буква слова -> список номерів (нумерація з 1)
        self._by_letter = {}
        for i, word in enumerate(self.words, start=1):
            self._by_letter.setdefault(word[0], []).append(i)

    def _tokenize(self, text):
        word, words = [], []
        for ch in text:
            if ch.isalpha():
                word.append(ch.lower())
            elif word:
                words.append("".join(word))
                word = []
        if word:
            words.append("".join(word))
        return words

    def encrypt(self, text, rng=None):
        rng = rng or random
        codes = []
        for word in self._tokenize(text):
            numbers = self._by_letter.get(word[0])
            if not numbers:
                raise CipherError(f"У ключі немає слова на літеру «{word[0]}»")
            codes.append(str(rng.choice(numbers)))
        if not codes:
            raise CipherError("Повідомлення не містить слів для шифрування")
        return " ".join(codes)

    def decrypt(self, ciphertext):
        result = []
        for token in ciphertext.split():
            if not token.isdigit():
                raise CipherError(f"Некоректний код: «{token}»")
            idx = int(token)
            if not 1 <= idx <= len(self.words):
                raise CipherError(f"Номер {idx} виходить за межі тексту-ключа")
            result.append(self.words[idx - 1][0].upper())
        # шифр відновлює лише перші літери слів - це властивість методу
        return " ".join(result)
