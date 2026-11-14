import unittest

from rsa_signature import RSASigner, SignatureError, HASHES


class TestRSASigner(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.signer = RSASigner("SHA-256")
        cls.pub, cls.priv = cls.signer.generate_keys(1024)

    def test_sign_and_verify(self):
        text = "Hello world!"
        sig = self.signer.sign(text, self.priv)
        self.assertTrue(self.signer.verify(text, sig, self.pub))

    def test_tampered_message_fails(self):
        sig = self.signer.sign("original message", self.priv)
        self.assertFalse(self.signer.verify("tampered message", sig, self.pub))

    def test_wrong_key_fails(self):
        other_pub, _ = RSASigner().generate_keys(1024)
        sig = self.signer.sign("повідомлення", self.priv)
        self.assertFalse(self.signer.verify("повідомлення", sig, other_pub))

    def test_sign_with_public_key_rejected(self):
        with self.assertRaises(SignatureError):
            self.signer.sign("abc", self.pub)

    def test_bad_private_key_rejected(self):
        with self.assertRaises(SignatureError):
            self.signer.sign("abc", "не ключ")

    def test_bad_signature_base64_fails(self):
        self.assertFalse(self.signer.verify("abc", "@@@ not base64", self.pub))

    def test_all_hash_algorithms(self):
        for name in HASHES:
            signer = RSASigner(name)
            pub, priv = signer.generate_keys(1024)
            sig = signer.sign("дані для підпису", priv)
            self.assertTrue(signer.verify("дані для підпису", sig, pub), name)

    def test_unknown_hash(self):
        with self.assertRaises(SignatureError):
            RSASigner("MD5")

    def test_hash_hex_stable(self):
        h1 = self.signer.hash_hex("test")
        h2 = self.signer.hash_hex("test")
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 64)  # SHA-256 -> 32 байти -> 64 hex

    def test_short_key_rejected(self):
        with self.assertRaises(SignatureError):
            RSASigner().generate_keys(512)


if __name__ == "__main__":
    unittest.main()
