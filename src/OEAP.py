import secrets
import hashlib

class OEAP(object):
    def __init__(self, g, h):
        self.G = g
        self.H = h

    @staticmethod
    def pad(m, size):
        bitsize = len(m) * 8

        assert bitsize <= size
        res = bytearray(m)

        for _ in range((size - bitsize) // 8):
            res.append(0)

        return res
    
    def G_hash(self, r):
        g = hashlib.sha1()
        g.update(r)

        x = g.digest()
        rem = self.G // 8

        if self.G > 160:
            while len(x) < self.G:
                x += x

        return x[:rem]

    def H_hash(self, x):
        h = hashlib.md5()
        h.update(x)

        y = h.digest()
        rem = self.H // 8

        if self.H > 128:
            while len(y) < self.H:
                y += y
        
        return y[:rem]
    
    @staticmethod
    def xor(a, b):
        assert len(bytearray(a)) == len(bytearray(b))

        return [a[i] ^ b[i] for i in range(len(a))]
    
    def encrypt(self, m1):
        b_m1 = OEAP.pad(m1.encode(), self.G)

        b_r = bytearray(secrets.token_bytes(self.H // 8))
        x = OEAP.xor(b_m1, self.G_hash(b_r))
        res = (x + OEAP.xor(b_r, self.H_hash(bytearray(x))))

        return ''.join(chr(i) for i in res)
    
    def decrypt(self, c):
        ind = self.G // 8
        x = [ord(char) for char in c[:ind]]
        y = [ord(char) for char in c[ind:]]
        r = OEAP.xor(self.H_hash(bytearray(x)), y)
        m1 = OEAP.xor(self.G_hash(bytearray(r)), x)

        return bytearray(m1[:16]).decode()