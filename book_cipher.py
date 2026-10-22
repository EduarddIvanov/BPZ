import random


class CipherError(Exception):
    pass


# типовий вірш-ключ (Некрасов, «Школьник») для демонстрації, як у методичці
DEFAULT_POEM = (
    "Ну пошел же ради бога\n"
    "Небо ельник и песок\n"
    "Невеселая дорога\n"
    "Эй садись ко мне дружок\n"
    "Ноги босы грязно тело\n"
    "И едва прикрыта грудь\n"
    "Не стыдися что за дело\n"
    "Это многих славный путь"
)


class PoemKey:
    """Ключ-вірш, записаний у прямокутну таблицю заданого розміру.

    Кожен символ ключа має координати (рядок, стовпець). Зайві символи рядка,
    що виходять за межі ширини таблиці, відкидаються - як у класичному
    віршованому шифрі.
    """

    def __init__(self, poem, rows=10, cols=10):
        if not isinstance(poem, str) or not poem.strip():
            raise CipherError("Вірш-ключ не може бути порожнім")
        if rows < 1 or cols < 1:
            raise CipherError("Розмір таблиці має бути додатнім")

        self.rows = rows
        self.cols = cols
        self.grid = self._build_grid(poem, rows, cols)
        self._positions = self._index_positions(self.grid)

        if not self._positions:
            raise CipherError("Таблиця ключа порожня")

    def _build_grid(self, poem, rows, cols):
        grid = []
        for line in poem.splitlines():
            letters = [ch.lower() for ch in line if ch.isalpha()]
            if not letters:
                continue
            grid.append(letters[:cols])  # зайві літери рядка викидаються
            if len(grid) == rows:
                break
        return grid

    def _index_positions(self, grid):
        # символ -> список координат (рядок, стовпець), нумерація з 1
        positions = {}
        for r, row in enumerate(grid):
            for c, ch in enumerate(row):
                positions.setdefault(ch, []).append((r + 1, c + 1))
        return positions

    def coords_for(self, ch):
        return self._positions.get(ch.lower(), [])

    def char_at(self, row, col):
        if 1 <= row <= len(self.grid) and 1 <= col <= len(self.grid[row - 1]):
            return self.grid[row - 1][col - 1]
        raise CipherError(f"Координати {row}/{col} виходять за межі таблиці")

    def alphabet(self):
        return sorted(self._positions)


class BookCipher:
    """Віршований книжковий шифр: символ -> координати у таблиці-вірші."""

    def encrypt(self, text, key, rng=None):
        if not isinstance(text, str):
            raise CipherError("Очікується рядок")
        rng = rng or random
        codes = []
        for ch in text:
            if not ch.isalpha():
                continue  # кодуємо лише літери, що є в таблиці
            variants = key.coords_for(ch)
            if not variants:
                raise CipherError(f"Символ «{ch}» відсутній у ключі-вірші")
            row, col = rng.choice(variants)
            codes.append(f"{row:02d}/{col:02d}")
        if not codes:
            raise CipherError("Повідомлення не містить символів для шифрування")
        return ", ".join(codes)

    def decrypt(self, ciphertext, key):
        if not isinstance(ciphertext, str):
            raise CipherError("Очікується рядок")
        result = []
        for token in ciphertext.split(","):
            token = token.strip()
            if not token:
                continue
            result.append(self._decode_token(token, key))
        if not result:
            raise CipherError("Шифрограма порожня")
        return "".join(result)

    def _decode_token(self, token, key):
        parts = token.replace(" ", "").split("/")
        if len(parts) != 2 or not all(p.isdigit() for p in parts):
            raise CipherError(f"Некоректний код: «{token}»")
        row, col = int(parts[0]), int(parts[1])
        return key.char_at(row, col)
