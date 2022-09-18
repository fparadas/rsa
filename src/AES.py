import secrets, string

def aesKeyGenerator():
        aesKeyLength = 16                       #16 bytes = 128 bits | 1 char = 1 byte
        K = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(aesKeyLength)) #returns a randomly generated string
        return K

print(aesKeyGenerator())