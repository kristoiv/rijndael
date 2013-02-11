#include <iostream>
#include <string>
#include "rijndael.h"

int main()
{
    Rijndael::Block key;
    key.set(0, 0, 0x2b);
    key.set(0, 1, 0x28);
    key.set(0, 2, 0xab);
    key.set(0, 3, 0x09);

    key.set(1, 0, 0x7e);
    key.set(1, 1, 0xae);
    key.set(1, 2, 0xf7);
    key.set(1, 3, 0xcf);

    key.set(2, 0, 0x15);
    key.set(2, 1, 0xd2);
    key.set(2, 2, 0x15);
    key.set(2, 3, 0x4f);
    
    key.set(3, 0, 0x16);
    key.set(3, 1, 0xa6);
    key.set(3, 2, 0x88);
    key.set(3, 3, 0x3c);

    Rijndael::Cipher cipher(key);

    std::string ciphertext = cipher.encrypt("ABCDEFGHIJKLMNOPQRSTUVXYZÆØÅ");
    std::cout << "Ciphertext (base64 encoded): " << ciphertext << std::endl;
    std::cout << "Plaintext: " << cipher.decrypt(ciphertext) << std::endl;

    return 0;
}

