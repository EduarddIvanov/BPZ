from caesar import CaesarCipher

# найчастіші літери для оцінки того, який варіант схожий на осмислений текст
FREQUENT = {
    "uk": "оаніивтес",
    "en": "etaoinshr",
}


class BruteForceAttack:
    def __init__(self, lang="uk"):
        self.cipher = CaesarCipher(lang)
        self.lang = lang
        self.n = self.cipher.n

    def _score(self, text):
        frequent = FREQUENT[self.lang]
        return sum(1 for ch in text.lower() if ch in frequent)

    def attack(self, ciphertext):
        results = []
        for key in range(1, self.n):
            guess = self.cipher.decrypt(ciphertext, key)
            results.append((key, guess, self._score(guess)))
        results.sort(key=lambda item: item[2], reverse=True)
        return results

    def best_guess(self, ciphertext):
        return self.attack(ciphertext)[0]
