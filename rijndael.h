#ifndef RIJNDAEL_H
#define RIJNDAEL_H

#include <string>
#include <cstring>

namespace Rijndael
{

    class Block
    {
    protected:
        unsigned char _grid[4][4];

    public:
        unsigned char get(unsigned char x, unsigned char y) { return _grid[x][y]; }
        void set(unsigned char x, unsigned char y, unsigned char v) { _grid[x][y] = v; }
    };

    class Cipher
    {
    protected:
        Block _keychain[11];

        void  _keyExpansion(Block key);
        Block _subBytes(Block state);
        Block _reverseSubBytes(Block state);
        Block _shiftRows(Block state);
        Block _reverseShiftRows(Block state);
        Block _mixColumns(Block state);
        Block _reverseMixColumns(Block state);
        Block _addRoundKey(Block state, Block key);

    public:
        Cipher(Block key) { _keyExpansion(key); }
        Block encrypt(Block state);
        Block decrypt(Block state);
        std::string encrypt(std::string plaintext);
        std::string decrypt(std::string ciphertext);
    };

    std::string base64_encode(unsigned char *, unsigned int);
    unsigned char * base64_decode(std::string);

};

#endif

