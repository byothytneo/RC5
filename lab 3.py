import secrets

# Constants for RC5
RC5_CONST = {
    16: (0xB7E1, 0x9E37),
    32: (0xB7E15163, 0x9E3779B9),
    64: (0xB7E151628AED2A6B, 0x9E3779B97F4A7C15),
}

# Default parameters
ROUNDS_DEFAULT = 12
BLOCKSIZE_DEFAULT = 64
KEYSIZE_DEFAULT = 128
IN_FILENAME = 'original_message.txt'
OUT_FILENAME = 'encrypted_message.txt'
DECRYPTED_FILENAME = 'decrypted_message.txt'

class RC5Cipher:
    def __init__(self, w: int, r: int, key: bytes):
        self.w, self.r, self.key = w, r, key
        self.u = w // 8
        self.b = len(key)
        self._prepare_key()

    def _prepare_key(self):
        self._align_key()
        self._extend_key()
        self._mix_key()

    def _align_key(self):
        while len(self.key) % self.u != 0:
            self.key += b"\x00"
        self.L = [int.from_bytes(self.key[i:i + self.u], 'little') for i in range(0, self.b, self.u)]

    def _extend_key(self):
        P, Q = RC5_CONST[self.w]
        self.S = [P] + [(P + i * Q) % (2**self.w) for i in range(1, 2 * self.r + 2)]

    def _mix_key(self):
        A = B = i = j = 0
        v = 3 * max(len(self.L), len(self.S))
        for _ in range(v):
            A = self.S[i] = self._rotate_left((self.S[i] + A + B) % (2**self.w), 3)
            B = self.L[j] = self._rotate_left((self.L[j] + A + B) % (2**self.w), (A + B) % self.w)
            i = (i + 1) % len(self.S)
            j = (j + 1) % len(self.L)

    def _rotate_left(self, x, n):
        n = n % self.w  # Убедитесь, что n находится в пределах размера слова
        return ((x << n) & (2**self.w - 1)) | (x >> (self.w - n))

    def _rotate_right(self, x, n):
        n = n % self.w  # Убедитесь, что n находится в пределах размера слова
        return (x >> n) | ((x << (self.w - n)) & (2**self.w - 1))

    def encrypt_block(self, message):
        A = message >> self.w
        B = message & (2**self.w - 1)
        A = (A + self.S[0]) % (2**self.w)
        B = (B + self.S[1]) % (2**self.w)
        for i in range(1, self.r + 1):
            A = (self._rotate_left(A ^ B, B) + self.S[2 * i]) % (2**self.w)
            B = (self._rotate_left(B ^ A, A) + self.S[2 * i + 1]) % (2**self.w)
        return (A << self.w) | B

    def decrypt_block(self, message):
        A = message >> self.w
        B = message & (2**self.w - 1)
        for i in range(self.r, 0, -1):
            B = self._rotate_right((B - self.S[2 * i + 1]) % (2**self.w), A) ^ A
            A = self._rotate_right((A - self.S[2 * i]) % (2**self.w), B) ^ B
        A = (A - self.S[0]) % (2**self.w)
        B = (B - self.S[1]) % (2**self.w)
        return (A << self.w) | B

    def encrypt_message(self, iv, in_fp, out_fp):
        with open(in_fp, 'rb') as inf, open(out_fp, 'wb') as outf:
            iv = self.decrypt_block(iv)
            outf.write(iv.to_bytes(self.u * 2, 'little'))
            while chunk := inf.read(self.u * 2):
                if len(chunk) != self.u * 2:
                    chunk = chunk.ljust(self.u * 2, b'\x00')
                data = self.encrypt_block(int.from_bytes(chunk, 'big') ^ iv)
                iv = data
                outf.write(data.to_bytes(self.u * 2, 'little'))

    def decrypt_message(self, in_fp, out_fp):
        with open(in_fp, 'rb') as inf, open(out_fp, 'wb') as outf:
            iv = int.from_bytes(inf.read(self.u * 2), 'little')
            while chunk := int.from_bytes(inf.read(self.u * 2), 'little'):
                data = self.decrypt_block(chunk) ^ iv
                outf.write(data.to_bytes(self.u * 2, 'big').rstrip(b'\x00'))
                iv = chunk

if __name__ == "__main__":
    rounds = int(input('Введите количество раундов (по умолчанию - 12): ') or ROUNDS_DEFAULT)
    blocksize = int(input('Введите размер блока в битах (по умолчанию - 64): ') or BLOCKSIZE_DEFAULT)
    keysize = int(input('Введите размер ключа в битах (по умолчанию - 128): ') or KEYSIZE_DEFAULT)
    message = input('Введите сообщение (по умолчанию из файла original_message.txt): ')

    if message:
        with open(IN_FILENAME, 'w', encoding='utf-8') as f:
            f.write(message)

    with open(IN_FILENAME, encoding='utf-8') as f:
        message = f.read()
        print(f'\nВаше сообщение:\n{message}')

    iv = secrets.randbits(keysize)
    key = iv.to_bytes(keysize // 8, byteorder='little')
    print(f'\nКлюч: {key}')

    rc5 = RC5Cipher(blocksize, rounds, key)
    rc5.encrypt_message(iv, IN_FILENAME, OUT_FILENAME)
    
    rc5 = RC5Cipher(blocksize, rounds, key)
    rc5.decrypt_message(OUT_FILENAME, DECRYPTED_FILENAME)

    with open(DECRYPTED_FILENAME, encoding='utf-8') as f:
        result = f.read()
        assert message == result
        print(f'\nРезультат работы шифра записан в {OUT_FILENAME}')
        print(f'\nРезультат дешифрования записан в {DECRYPTED_FILENAME}')
        print(f'Результат дешифрования:\n{result}')
