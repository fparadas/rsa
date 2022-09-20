from AES import AES

if __name__ == "__main__":


    #### AES TEST
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    check = (
        ("6bc1bee22e409f96e93d7e117393172a", "3ad77bb40d7a3660a89ecaf32466ef97"),
        ("ae2d8a571e03ac9c9eb76fac45af8e51", "f5d3d58503b9699de785895a96fdbaaf"),
        ("30c81c46a35ce411e5fbc1191a0a52ef", "43b1cd7f598ece23881b00e3ed030688"),
        ("f69f2445df4f9b17ad2b417be66c3710", "7b0c785e27e8ad3f8223207104725dd4"),
    )
    crypt = AES(key)
    for clear_hex, encoded_hex in check:
        clear_bytes = bytes.fromhex(clear_hex)
        encoded_bytes = bytes.fromhex(encoded_hex)
        t = crypt.cipher(clear_bytes)
        if t == encoded_bytes:
            print("yay!")
        else:
            print("{0} != {1}".format(t.hex(), encoded_hex))
        t = crypt.decipher(encoded_bytes)
        if t == clear_bytes:
            print("yay!")
        else:
            print("{0} != {1}".format(t.hex(), clear_hex))