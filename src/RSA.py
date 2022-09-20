import random
import math
import secrets

class RSA(object):
    prime_list = []
    def __init__(self, bitsize):
        self.bitsize = 2**bitsize - 1
        self.sieve_eratosthenes()
    
    def sieve_eratosthenes(self):
        prime = [True for _ in range(self.bitsize + 1)]
        p = 2
        while (p**2 <= self.bitsize):
            if prime[p]:
                for i in range(p**2, self.bitsize + 1, p):
                    prime[i] = False

            p += 1
        
        self.prime_list = [x for x in range(2, self.bitsize + 1) if prime[x]]

    def get_low_prime(self):
        while True:
            test = random.randrange(((self.bitsize+1) >> 1) + 1, self.bitsize)

            for divisor in self.prime_list:
                if test % divisor == 0 and divisor**2 <= test:
                    break
                else: return test
    
    def miller_robin_test(self, candidate):
        max_div_by_two = 0
        even = candidate - 1

        while even % 2 == 0:
            even >>= 1
            max_div_by_two += 1
        
        assert (2**max_div_by_two)*even == candidate - 1

        def round(tester):
            if pow(tester, even, candidate) == 1:
                return False
            
            for i in range(max_div_by_two):
                if pow(tester, (2**i)*even, candidate) == candidate - 1:
                    return False
            
            return True

        
        for _ in range(20):
            tester = random.randrange(2, candidate)
            if round(tester):
                return False
        
        return True
    
    def gen_prime(self):
        while True:
            candidate = self.get_low_prime()

            if self.miller_robin_test(candidate):
                return candidate   

    @staticmethod
    def eucalg(a, b):
        #euclidian extended gcd
        swapped = False
        if a < b:
            a, b = b, a
            swapped = True
        
        ca = (1, 0)
        cb = (0, 1)

        while b != 0:
            k = a // b

            a, b, ca, cb = b, a-b*k, cb, (ca[0] - k*cb[0], ca[1] - k*cb[1])
        
        if swapped:
            return (ca[1], ca[0])
        
        return ca
    

    
    @staticmethod
    def cipher(key, text):
        k, n = key

        return [pow(ord(char), k, n) for char in text]

    @staticmethod
    def decipher(key, text):
        k, n = key

        return ''.join(chr(pow(char, k, n)) for char in text)

    def key_gen(self, pq=None):
        if not pq:
            p = self.gen_prime()
            q = self.gen_prime()
        else:
            p, q = pq

        while p == q:
            q = self.gen_prime()
        
        n = p*q
        lambda_n = (p-1)*(q-1)
        e = random.randrange(1,lambda_n)

        while math.gcd(e, lambda_n) != 1:
            e = random.randrange(1,lambda_n)
        
        d = RSA.eucalg(e, lambda_n)[0]
        if d < 0: d += lambda_n

        return {"private": (d, n), "public": (e, n)}