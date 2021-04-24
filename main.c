#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <math.h>

#define ROR(x, r) ((x >> r) | (x << (32 - r)))
#define ROL(x, r) ((x << r) | (x >> (32 - r)))

// function for converting Hex String to a 64-bit integer
uint64_t fromHexStringToLong(char *block) {
    uint64_t result;
    int i;
    // each character is 4 bits, there are 16 characters in a 64-bit block
    // the multiplication and addition are done the same way as before, with shifting and bitwise OR
    for (i = 0; i < 16; i++)
        result = (result << 4) | ((block[i] >= '0' && block[i] <= '9') ? (block[i] - '0') : (block[i] - 'a' + 10));
    return result;
}

// function for converting a 64-bit integer to a Hex String
char *fromLongToHexString(uint64_t block) {
    char *hexString = malloc(17 * sizeof(char));
    //we print the integer in a String in hexadecimal format
    sprintf(hexString, "%016llx", block);
    return hexString;
}

// function that returns the low 64 bits of the key, which is given as input in a Hex String format
uint64_t getKeyLow(char *key) {
    int i;
    uint64_t keyLow = 0;
    //the least significant 16 bits are the last 4 characters of the key
    for (i = 16; i < 32; i++)
        //again, multiplication and addition are done using bitwise left shift and bitwise OR
        keyLow = (keyLow << 4) | (((key[i] >= '0' && key[i] <= '9') ? (key[i] - '0') : (key[i] - 'a' + 10)) & 0xF);
    return keyLow;
}

uint32_t form32BitBlock(uint32_t key) {
    return ((uint32_t) ((uint8_t) key) << 24 | (uint32_t) (uint8_t) (key >> 8) << 16 |
            (uint32_t) (uint8_t) (key >> 16) << 8 | (uint32_t) (uint8_t) (key >> 24));
}

// function that generates subKeys from the key according to the SIMON key scheduling algorithm for a 128-bit key
uint32_t *generateSubkeys(char *key) {
    //the 128 bit key is placed in two integers, both of them are 64 bit
    uint64_t KeyHigh = fromHexStringToLong(key);
    uint64_t KeyLow = getKeyLow(key);
    uint64_t z3 = 0xfc2ce51207a635dbLL;
    uint32_t c = 0xfffffffc;

    //we allocate space for 32 subkeys, since there are 32 rounds
    uint32_t *roundKeys = malloc(44 * (sizeof(uint32_t)));

    roundKeys[0] = form32BitBlock(KeyHigh >> 32);
    roundKeys[1] = form32BitBlock(KeyHigh);
    roundKeys[2] = form32BitBlock(KeyLow >> 32);
    roundKeys[3] = form32BitBlock(KeyLow);

    for (int i = 4; i < 44; ++i) {
        uint32_t test = ROR(roundKeys[i - 1], 3);
        roundKeys[i] = c ^ (z3 & 1) ^ roundKeys[i - 4] ^ ROR(roundKeys[i - 1], 3) ^ roundKeys[i - 3]
                       ^ ROR(roundKeys[i - 1], 4) ^ ROR(roundKeys[i - 3], 1);
        z3 >>= 1;
    }
//    for (int i = 0; i < 44; i++) {
//        printf("roundKeys[%d] = %" PRIx32 "\n", i, roundKeys[i]);
//    }
    return roundKeys;
}

// function for encrypting a block using a key
char *encrypt(char *plaintext, char *key) {
    //generate the subkeys using the function defined above
    uint32_t *roundKeys = generateSubkeys(key);
    //convert the plaintext from a Hex String to a 64-bit integer
    uint64_t state = fromHexStringToLong(plaintext);
    //split block of plain text into 2 blocks.
    uint32_t rightPlainBlock = form32BitBlock(state >> 32);
    uint32_t leftPlainBlock = form32BitBlock(state);

    for (int i = 0; i < 44; i++) {

        uint32_t temp = leftPlainBlock;
        leftPlainBlock = rightPlainBlock ^ ((ROL(leftPlainBlock, 1) & ROL(leftPlainBlock, 8))
                                            ^ ROL(leftPlainBlock, 2)) ^ roundKeys[i];
        rightPlainBlock = temp;
//        printf("cipher round [%d] = %" PRIx32 ", %" PRIx32 "\n", i, leftPlainBlock, rightPlainBlock);
    }

    state = state & 0;
    state = ((state | leftPlainBlock) << 32) | rightPlainBlock;

    return fromLongToHexString(state);

}

// function for decrypting a block using a key
char *decrypt(char *ciphertext, char *key) {
    //generate the subkeys using the function defined above
    uint32_t *roundKeys = generateSubkeys(key);
    //convert the plaintext from a Hex String to a 64-bit integer
    uint64_t state = fromHexStringToLong(ciphertext);
    //split block of plain text into 2 blocks.
    uint32_t rightCipherBlock = state;
    uint32_t leftCipherBlock = state >> 32;

    for (int i = 43; i >= 0; i--) {
        uint32_t temp = rightCipherBlock;
        rightCipherBlock =
                leftCipherBlock ^ ((ROL(rightCipherBlock, 1) & ROL(rightCipherBlock, 8))
                ^ ROL(rightCipherBlock, 2)) ^ roundKeys[i];
        leftCipherBlock = temp;
//        printf("cipher round [%d] = %" PRIx32 ", %" PRIx32 "\n", i, leftCipherBlock, rightCipherBlock);
    }


    state = state & 0;
    state = ((state | leftCipherBlock) << 32) | rightCipherBlock;

    return fromLongToHexString(state);
}


// Test main function
int main() {
    //declare a pointer and allocate memory for the plaintext (1 block) and the key
    char *plaintext = malloc(17 * sizeof(char));
    char *key = malloc(34 * sizeof(char));

    //declare a pointer for the ciphertext
    char *ciphertext;
    //code for entering the plaintext and the key
    printf("Enter the plaintext (64 bits) in hexadecimal format\nUse lower case characters and enter new line at the end\n");
    gets(plaintext);
    printf("Enter the key (128 bits) in hexadecimal format\nUse lower case characters and enter new line at the end\n");
    gets(key);
//    plaintext = "756e64206c696b65";
//    key = "0001020308090a0b1011121318191a1b";
    //calling the encrypt function
    ciphertext = encrypt(plaintext, key);
    //printing the result
    printf("The ciphertext is: ");
    puts(ciphertext);
    printf("The decrypted plaintext is: ");
    //calling the decrypt function and printing the result
    puts(decrypt(ciphertext, key));
    //freeing the allocated memory
    free(key);
    free(plaintext);
    free(ciphertext);
    return 0;
}
