// preprocessor director include with header aes.h in quotation instead of angled brackets

#include "aes.h"
#include <stdlib.h>

int main(){


    //static storage duration array objects. lifetime throughout program
    //16 byte key
    unsigned char cipher_key[16] = {
        0x2b, 0x28, 0xab, 0x09, 0x7e, 0xae, 0xf7, 0xcf,
        0x15, 0xd2, 0x15, 0x4f, 0x16, 0xa6, 0x88, 0x3c
    };

    unsigned char plaintext[16] = {
        0x32, 0x88, 0x31, 0xe0, 0x43, 0x5a, 0x31, 0x37,
        0xf6, 0x30, 0x98, 0x07, 0xa8, 0x8d, 0xa2, 0x34
    };

    //calculating the round keys for the encryption algorithm
    unsigned char round_key[177];
    key_schedule(cipher_key, round_key);

    //automatic storage given to encryption block, begining when it begins, ending when it ends
    encrypt_block(plaintext, cipher_key, round_key); 
 
    unsigned char cipher_text[16];

    // dynamically allocated memory is allocated from the heap, the heap is a large subdivisable block, when memory is allocated
    // the caller managers the memory, dynamically memory allocation is used when exact storage requirements are unknown before runtime like here
    // use sizeof to calculate the size of objects,  malloc returns a pointer to the allocated space, no type until an object is copied into the storage
    void *p = malloc(sizeof(cipher_text));
    
    // giving the cipher text the value from the plaintext encryption alterations 
    for(int i=0; i<16; i++){
        cipher_text[i]= plaintext[i];
    } 
    printf("------------------------------\n");
    printf("Cipher text after encryption:\n");
    printf("------------------------------\n");
    for(int i=0; i<16; i++){
        // % x translates the decimal value into hex for us to see
        printf("%x\n", cipher_text[i]);
    }
    printf("-------------------------------\n");
    
    //automatic storage given to decryption block, begining when it begins, ending when it ends
    decrypt_block(cipher_key, cipher_text, round_key);
    
    // giving the plain text the value from the cipher text encryption alterations
    for(int i=0; i<16; i++){
        plaintext[i]= cipher_text[i];
    } 
    
    printf("Plaintext after decryption:\n");
    printf("--------------------------------\n");
    for(int i=0; i<16; i++){
        // % x translates the decimal value into hex for us to see
        printf("%x\n", plaintext[i]);
    }
    printf("--------------------------------\n");

    //deallocated allocated memory for p
    void free(void *p);
    return 0;

    //free pointers if allocated any space on heap internally

}
