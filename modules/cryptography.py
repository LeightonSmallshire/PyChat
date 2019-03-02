from secrets import randbelow


# noinspection PyPep8Naming
class RC4:
    """Based on equivalent code written in C on wikipedia; https://en.wikipedia.org/wiki/RC4"""

    @staticmethod
    def KSA(key: tuple):  # key-scheduling algorithm
        keylen = len(key)  # Number of bytes in key (typically 5-16 but must be 1-256)
        S = [*range(256)]  # List counting 0 to 255
        j = 0

        for i in range(256):
            j = (j + S[i] + key[i % keylen]) & 255
            S[i], S[j] = S[j], S[i]  # swap values
        return S

    @staticmethod
    def PRGA(S: list):  # pseudo-random generation algorithm
        i, j = 0, 0
        while True:
            i = (i + 1) & 255
            j = (j + S[i]) & 255
            S[i], S[j] = S[j], S[i]  # swap values
            yield S[(S[i] + S[j]) & 255]  # yields bytes at a time (as integers)

    # Convenience functions
    @staticmethod
    def convert_int_key(key: int) -> tuple:
        assert key > 0 and key.bit_length() <= 8 * 256  # Key positive and at most 256 bytes
        # Split the int into bytes (big-endian) and return the tuple of byte values
        return tuple(int.to_bytes(key, (key.bit_length() + 7) >> 3, 'big'))

    @staticmethod
    def convert_str_key(key: str) -> tuple:
        assert 0 <= len(key) <= 256
        return tuple(ord(c) for c in key)

    @staticmethod
    def generate(key: tuple):  # Generate the bytestream
        yield from RC4.PRGA(RC4.KSA(key))

    @classmethod
    def crypt_str(cls, gen, plaintext: str, encoding='utf-8') -> bytes:  # Encrypt a string with the generator
        return cls.crypt_bytes(gen, plaintext.encode(encoding))

    @staticmethod
    def crypt_bytes(gen, plaintext: bytes):  # Encrypt bytes with the generator
        return bytes((p ^ next(gen) for p in plaintext))


class DHE:
    """Diffie Hellman Key Exchange"""
    # From RFC 3526 - https://tools.ietf.org/html/rfc3526.html
    groups = {
        # GroupID: (generator, prime)
        None: (None, None),  # Used for testing. Intentionally crashes if used normally.
        14: (2, int(
            ('FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 '
             '8E3404DD EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9 A637ED6B '
             '0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D C2007CB8 A163BF05 98DA4836 '
             '1C55D39A 69163FA8 FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D 670C354E 4ABC9804 '
             'F1746C08 CA18217C 32905E46 2E36CE3B E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 '
             '95581718 3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AACAA68 FFFFFFFF FFFFFFFF').replace(' ', ''), 16)),
    }

    def __init__(self, group_id: int, private: int = None):
        """
        Create a DH object and generate a private key.
        :param group_id: The RFC-specified group of values.
        """
        assert group_id in self.groups.keys(), f'Invalid group id; {group_id}'
        self.group_id: int = group_id
        self.g, self.p = self.groups[group_id]
        self._private: int = private or randbelow(self.p - 2) + 1  # Between 1 and p-1
        self.public: int = self.calc(self.g, self._private, self.p)
        self.secret: int = 0

    # noinspection PyTypeChecker
    @classmethod
    def test_init(cls, generator: int, modulo: int, private: int):
        """Creates an instance, with fully custom parameters."""
        cls.groups[None] = (generator, modulo)  # Set the test group's settings
        inst = cls(None, private)  # Initialize normally
        cls.groups[None] = (None, None)  # Reset to invalid values
        return inst

    @staticmethod
    def calc(generator, exponent, modulo):
        return pow(generator, exponent, modulo)

    def update(self, other_public: int) -> int:
        assert 1 <= other_public <= self.p - 1, 'Invalid public key'
        self.secret = self.calc(other_public, self._private, self.p)
        return self.secret
