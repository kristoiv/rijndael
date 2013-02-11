#include "rijndael.h"
#include <iostream>
#include <vector>
#include <stdint.h>

namespace Rijndael
{

    static const unsigned char sboxTable[256] = {
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
        0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
        0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
        0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
        0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
        0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
        0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
        0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
        0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
        0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
        0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
        0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
        0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
        0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
        0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
        0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
        0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
    };

	static const unsigned char reverseSboxTable[256] = {
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38,
        0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
        0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87,
        0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
        0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D,
        0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
        0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2,
        0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
        0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16,
        0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
        0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA,
        0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
        0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A,
        0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
        0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02,
        0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
        0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA,
        0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
        0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85,
        0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
        0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89,
        0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
        0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20,
        0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
        0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31,
        0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
        0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D,
        0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
        0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0,
        0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26,
        0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
    };

    static const unsigned char rconTable[256] = {
        0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 
        0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 
        0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 
        0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 
        0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 
        0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 
        0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 
        0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 
        0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 
        0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 
        0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 
        0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 
        0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 
        0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 
        0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 
        0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d
    };

    uint8_t gmul(uint8_t a, uint8_t b)
    {
        uint8_t p = 0;
        uint8_t counter;
        uint8_t hi_bit_set;
        for (counter = 0; counter < 8; counter++) {
            if (b & 1) p ^= a;
            hi_bit_set = (a & 0x80);
            a <<= 1;
            if (hi_bit_set) a ^= 0x1b;
            b >>= 1;
        }
        return p;
    }

    void Cipher::_keyExpansion(Block key)
    {
        _keychain[0] = key;

        for(int r = 1; r <= 10; r++) {

            Block rKey;

            unsigned char c[4];
            c[0] = _keychain[r-1].get(0, 3);
            c[1] = _keychain[r-1].get(1, 3);
            c[2] = _keychain[r-1].get(2, 3);
            c[3] = _keychain[r-1].get(3, 3);

            unsigned char temp = c[0];
            c[0] = c[1];
            c[1] = c[2];
            c[2] = c[3];
            c[3] = temp;

            for(int i = 0; i < 4; i++) {
                unsigned char low  = c[i] & 15;
                unsigned char high = c[i] >> 4;
                c[i] = sboxTable[high * 16 + low];
            }

            rKey.set(0, 0, _keychain[r-1].get(0, 0) ^ c[0] ^ rconTable[r]);
            rKey.set(1, 0, _keychain[r-1].get(1, 0) ^ c[1] ^ 0x00);
            rKey.set(2, 0, _keychain[r-1].get(2, 0) ^ c[2] ^ 0x00);
            rKey.set(3, 0, _keychain[r-1].get(3, 0) ^ c[3] ^ 0x00);

            for(int i = 1; i < 4; i++) {
                c[0] = rKey.get(0, i-1);
                c[1] = rKey.get(1, i-1);
                c[2] = rKey.get(2, i-1);
                c[3] = rKey.get(3, i-1);
                rKey.set(0, i, _keychain[r-1].get(0, i) ^ c[0]);
                rKey.set(1, i, _keychain[r-1].get(1, i) ^ c[1]);
                rKey.set(2, i, _keychain[r-1].get(2, i) ^ c[2]);
                rKey.set(3, i, _keychain[r-1].get(3, i) ^ c[3]);
            }

            _keychain[r] = rKey;

        }
    }

    Block Cipher::_subBytes(Block state)
    {
        unsigned char low;
        unsigned char high;

        for(int x = 0; x < 4; x++) {
            for(int y = 0; y < 4; y++) {
                low  = state.get(x, y) & 15;
                high = state.get(x, y) >> 4;
                state.set(x, y, sboxTable[high * 16 + low]);
            }
        }

        return state;
    }

    Block Cipher::_reverseSubBytes(Block state)
    {
        unsigned char low;
        unsigned char high;

        for(int x = 0; x < 4; x++) {
            for(int y = 0; y < 4; y++) {
                low  = state.get(x, y) & 15;
                high = state.get(x, y) >> 4;
                state.set(x, y, reverseSboxTable[high * 16 + low]);
            }
        }

        return state;
    }

    Block Cipher::_shiftRows(Block state)
    {
        unsigned char temp;

        for(int i = 1; i < 4; i++) {
            for(int j = 0; j < i; j++) {
                temp = state.get(i, 0);
                state.set(i, 0, state.get(i, 1));
                state.set(i, 1, state.get(i, 2));
                state.set(i, 2, state.get(i, 3));
                state.set(i, 3, temp);
            }
        }

        return state;
    }

    Block Cipher::_reverseShiftRows(Block state)
    {
        unsigned char temp;

        for(int i = 1; i < 4; i++) {
            for(int j = 0; j < i; j++) {
                temp = state.get(i, 3);
                state.set(i, 3, state.get(i, 2));
                state.set(i, 2, state.get(i, 1));
                state.set(i, 1, state.get(i, 0));
                state.set(i, 0, temp);
            }
        }

        return state;
    }

    Block Cipher::_mixColumns(Block state)
    {
        for(int y = 0; y < 4; y++) {

            unsigned char r[4];
            r[0] = state.get(0, y);
            r[1] = state.get(1, y);
            r[2] = state.get(2, y);
            r[3] = state.get(3, y);
            unsigned char a[4];
            unsigned char b[4];
            unsigned char h;

            for(unsigned char c = 0; c < 4; c++) {
                    a[c] = r[c];
                    h = (unsigned char)((signed char)r[c] >> 7);
                    b[c] = r[c] << 1;
                    b[c] ^= 0x1B & h;
            }

            r[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1]; /* 2 * a0 + a3 + a2 + 3 * a1 */
            r[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2]; /* 2 * a1 + a0 + a3 + 3 * a2 */
            r[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3]; /* 2 * a2 + a1 + a0 + 3 * a3 */
            r[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0]; /* 2 * a3 + a2 + a1 + 3 * a0 */

            state.set(0, y, r[0]);
            state.set(1, y, r[1]);
            state.set(2, y, r[2]);
            state.set(3, y, r[3]);

        }

        return state;
    }

    Block Cipher::_reverseMixColumns(Block state)
    {
        for(int y = 0; y < 4; y++) {

            unsigned char r[4];
            r[0] = state.get(0, y);
            r[1] = state.get(1, y);
            r[2] = state.get(2, y);
            r[3] = state.get(3, y);
            unsigned char a[4];
            unsigned char b[4];
            unsigned char h;

            for(unsigned char c = 0; c < 4; c++) {
                    a[c] = r[c];
                    h = (unsigned char)((signed char)r[c] >> 7);
                    b[c] = r[c] << 3;
                    b[c] ^= 0x1B & h;
            }

            r[0] = gmul(14, a[0]) ^ gmul(9, a[3]) ^ gmul(13, a[2]) ^ gmul(11, a[1]); /* 14 * a0 + 9 * a3 + 13 * a2 + 11 * a1 */
            r[1] = gmul(14, a[1]) ^ gmul(9, a[0]) ^ gmul(13, a[3]) ^ gmul(11, a[2]); /* 14 * a1 + 9 * a0 + 13 * a3 + 11 * a2 */
            r[2] = gmul(14, a[2]) ^ gmul(9, a[1]) ^ gmul(13, a[0]) ^ gmul(11, a[3]); /* 14 * a2 + 9 * a1 + 13 * a0 + 11 * a3 */
            r[3] = gmul(14, a[3]) ^ gmul(9, a[2]) ^ gmul(13, a[1]) ^ gmul(11, a[0]); /* 14 * a3 + 9 * a2 + 13 * a1 + 11 * a0 */

            state.set(0, y, r[0]);
            state.set(1, y, r[1]);
            state.set(2, y, r[2]);
            state.set(3, y, r[3]);

        }

        return state;
    }

    Block Cipher::_addRoundKey(Block state, Block key)
    {
        for(int i = 0; i < 4; i++) {
            for(int j = 0; j < 4; j++) {
                state.set(i, j, state.get(i, j) ^ key.get(i, j));
            }
        }

        return state;
    }

    Block Cipher::encrypt(Block state)
    {
        state = _addRoundKey(state, _keychain[0]);

        for(int r = 1; r <= 10; r++) {
            state = _subBytes(state);
            state = _shiftRows(state);
            if( r != 10 ) state = _mixColumns(state);
            state = _addRoundKey(state, _keychain[r]);
        }

        return state;
    }

    Block Cipher::decrypt(Block state)
    {
        for(int r = 10; r > 0; r--) {
            state = _addRoundKey(state, _keychain[r]);
            if( r != 10 ) state = _reverseMixColumns(state);
            state = _reverseShiftRows(state);
            state = _reverseSubBytes(state);
        }

        state = _addRoundKey(state, _keychain[0]);

        return state;
    }

    std::string Cipher::encrypt(std::string plaintext)
    {
        // Create C-string, padd it to be devicable by 16 bytes.
        int s = plaintext.size();
        while( (s % 16) != 0 ) s++;
        char * p = new char[s];
        strcpy(p, plaintext.c_str());
        int i = plaintext.size();// + 1;
        while( i < s ) {
            p[i] = 0x00;
            i++;
        }

        // Construct the 128bit blocks (states).
        int blockCount = s/16;
        std::vector<Block> blocks;
        while( blockCount-- > 0 ) {
            Block block;
            for(int a = 0; a < 4; a++) {
                for(int b = 0; b < 4; b++) {
                    block.set(a, b, *(p++));
                }
            }
            blocks.push_back(block);
        }

        // Encrypt the each state and replace it back into the vector.
        for(std::vector<Block>::iterator it = blocks.begin(); it < blocks.end(); it++) {
            *it = encrypt(*it);
        }

        unsigned char out[s];
        int o = 0;

        // Create string ciphertext
        for(std::vector<Block>::iterator it = blocks.begin(); it < blocks.end(); it++) {
            for(int a = 0; a < 4; a++) {
                for(int b = 0; b < 4; b++) {
                    out[o++] = it->get(a, b);
                }
            }
        }

        return std::string(base64_encode(out, o));
    }

    std::string Cipher::decrypt(std::string ciphertext)
    {
        std::vector<Block> blocks;

        unsigned char * c = base64_decode(ciphertext);
        const char * t = (char *) c;
        unsigned int s = strlen(t);

        if( (s % 16) != 0 ) return std::string("");

        // Split up input into blocks (states).
        int blockCount = s/16;
        while( blockCount-- > 0 ) {
            Block state;
            for(int i = 0; i < 4; i++) {
                for(int j = 0; j < 4; j++) {
                    state.set(i, j, *(c++));
                }
            }
            blocks.push_back(state);
        }

        for(std::vector<Block>::iterator it = blocks.begin(); it < blocks.end(); it++) {
            *it = decrypt(*it);
        }

        std::string plaintext;

        for(std::vector<Block>::iterator it = blocks.begin(); it < blocks.end(); it++) {
            for(int i = 0; i < 4; i++) {
                for(int j = 0; j < 4; j++) {
                    plaintext += it->get(i, j);
                }
            }
        }

        return plaintext;
    }

    static inline bool is_base64(unsigned char c)
    {
        return (isalnum(c) || (c == '+') || (c == '/'));
    }

    std::string base64_encode(unsigned char * binary, unsigned int length)
    {
        static const std::string base64_chars = 
                     "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                     "abcdefghijklmnopqrstuvwxyz"
                     "0123456789+/";

        std::string ret;
        int i = 0;
        int j = 0;
        unsigned char char_array_3[3];
        unsigned char char_array_4[4];
        while (length--) {
            char_array_3[i++] = *(binary++);
            if (i == 3) {
                char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
                char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
                char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
                char_array_4[3] = char_array_3[2] & 0x3f;
                for(i = 0; (i <4) ; i++) ret += base64_chars[char_array_4[i]];
                i = 0;
            }
        }
        if(i) {
            for(j = i; j < 3; j++) char_array_3[j] = '\0';
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;
            for (j = 0; (j < i + 1); j++) ret += base64_chars[char_array_4[j]];
            while((i++ < 3)) ret += '=';
        }
        return ret;
    }

    unsigned char * base64_decode(std::string base64)
    {
        static const std::string base64_chars = 
                     "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                     "abcdefghijklmnopqrstuvwxyz"
                     "0123456789+/";

        int in_len = base64.size();
        int i = 0;
        int j = 0;
        int in_ = 0;
        unsigned char char_array_4[4], char_array_3[3];
        std::string ret;
        while (in_len-- && ( base64[in_] != '=') && is_base64(base64[in_])) {
            char_array_4[i++] = base64[in_]; in_++;
            if(i == 4) {
                for (i = 0; i <4; i++) char_array_4[i] = base64_chars.find(char_array_4[i]);
                char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
                char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
                char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
                for (i = 0; (i < 3); i++) ret += char_array_3[i];
                i = 0;
            }
        }
        if(i) {
            for (j = i; j <4; j++) char_array_4[j] = 0;
            for (j = 0; j <4; j++) char_array_4[j] = base64_chars.find(char_array_4[j]);
            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
            for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
        }
        char * str = new char[ret.size()];
        strcpy(str, ret.c_str());
        return (unsigned char *) str;
    }

};

