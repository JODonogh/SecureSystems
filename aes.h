//pre-processing "include" directive lead by # token
//pre-processor inserting the contents of one source file, stdio, into this one
//included files called header files, which insert contents of stdio.h into the file
#include <stdio.h>//header file library with input and output functions

//coding the cipher algorithm, to take the plaintext and turn into the ciphertext and decryption the other way around

//S-box= substition box, partial substition cipher. s-box is non-linear, and no statistical bias to keep it secure
char sub_box[] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
};

// declaring inverted s-box identifier & array datatype
char inv_s_box[256] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
};

// rcon array
unsigned char rcon [40] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00    
};

//function for each step 
 
void sub_bytes(unsigned char *plaintext){
    //substition part of the SPN(substitution-Permutation Network), it substitutes the bytes of the block passed to it in place
    //We go through each value from the plaintext and substitue (hence sub) the value from S-Box

    for (int i=0; i<16; i++){
            plaintext[i]= sub_box[ plaintext[i] ];
    }; 
};

void invert_sub_bytes(unsigned char *ciphertext){
    // invert-sub-bytes

    for (int i=0; i<16; i++){
            ciphertext[i]= inv_s_box[ ciphertext[i] ];
    };  

} 

void shift_rows(unsigned char *block){
    // shift rows- shift the a certain number of bytes, 2nd row by 1 byte, 3rd row by 2 bytes, 4th row by 3 bytes
     unsigned char temp= block[13];
    unsigned char temp2= block[1];
    block[13]= block[1];
    block[1]= block[5];
    temp2= block[5];
    block[5]=block[9]; 
    block[9]=temp;
    //shift 3rd row by 2 bytes
    temp= block[2];
    block[2]= block[10];
    temp2= block[6];
    block[6]= block[14];
    block[10]= temp;
    block[14]= temp2;
    //shift 4th row by 3 bytes
    temp= block[3];
    block[3] = block[15];
    temp2= block[11];
    block[15] = block[11];
    block[11]= block[7];
    block[7]= temp;
} ;

void invert_shift_rows(unsigned char *block){
    // invert-shift-rows- the same but the opposite direction, ie 2nd shift 3 bytes, 3rd row 2 bytes, 4th row 3 bytes. 
    //shift 2nd row by 3 bytes
    unsigned char temp= block[1];
    block[1]= block[13];
    block[13]= block[9];
    block[9]= block[5];
    block[5]=temp; 
    //shift 3rd row by 2 bytes
    unsigned char temp2= block[2];
    block[2]=block[10]; 
    block[10]= temp2;
    temp2= block[6];
    block[6]= block[14];
    block[14]=temp2;
    //shift 4th row by 1 bytes
    temp= block[3];
    block[3] = block[7];
    temp2 = block[7];
    block[7] = block[11];
    block[11]= block[15];
    block[15]= temp;
} 

unsigned char z_time(unsigned char a){
    //ternary operator with 3 parts, a bitwise AND expression before the ? and then if true (a<<1) ^ 0x1B), if false (a<<1), the result is returned
    // 0x80 is the short hand hexadecimal value for 10000000 which is the AND mask
    // shifting a value left by one place doubles its value e.g. 32 to 64, or 64 to 128
    // hexadecimal is a 16 bit counting system, so with 1b, you need to split it into its two binary values 
    // 1, the first 4 bits, in binary is 0001, and B is the second 4 bits, so 1011, resulting in 00011011 which is 27
    // so if true, whatever the inputted value of a is, is doubled or shifted one bit left, and this is XOR-ed with 00011011
    // XOR or Exclusive OR, if two bits are identical it returns 0, if they are different it returns true or 1
    // say a was 00000100 (which is 4), shifted left(doubled) becomes 8 or 00001000, so 00011011, so it would return 00010011 would be 19 would be returned if true
    // else 00001000 would be returned. 

    return (a & 0x80) ? ((a<<1) ^ 0x1B) : (a<<1);
};

void mix_single_column(unsigned char *a){
    // mix-columns- matrix multiplication, you take each column in the block and multiply it by matrix, this is matrix multiplication over a galois field
    unsigned char e = a[0] ^ a[1] ^ a[2] ^ a[3];
    unsigned char u= a[0];
    // XOR and assignment of s[i] with e XOR xtime a/b/c/d to the power of b/c/d/a
    // you substitute the row of the block with a row of the galois field
	a[0] ^= e ^ z_time(a[0]^ a[1]);
	a[1] ^= e ^ z_time(a[1]^ a[2]);
	a[2] ^= e ^ z_time(a[2]^ a[3]);
	a[3] ^= e ^ z_time(a[3]^ u);        
};

void mix_columns(unsigned char *plaintext){
    //breaking columns up to put them singly through the mixed single column
    unsigned char column_1[]= {plaintext[0], plaintext[1], plaintext[2], plaintext[3]};
    mix_single_column( column_1);
    unsigned char column_2[]= {plaintext[4], plaintext[5], plaintext[6], plaintext[7]};
    mix_single_column( column_2);
    unsigned char column_3[]= {plaintext[8], plaintext[9], plaintext[10], plaintext[11]};
    mix_single_column( column_3);
    unsigned char column_4[]= {plaintext[12], plaintext[13], plaintext[14], plaintext[15]};
    mix_single_column( column_4);

    //re-adding them together
    for(int i=0; i<4;i++){
        plaintext[i]= column_1[i];
    }
    for(int i=4; i<8;i++){
        plaintext[i]= column_1[i];
    }
    for(int i=8; i<12;i++){
        plaintext[i]= column_1[i];
    }
    for(int i=12; i<16;i++){
        plaintext[i]= column_1[i];
    }
    
};

void inv_mix_column(unsigned char *a){
    // inv mix-columns
    //you take each column in the block and multiply it by matrix, this is matrix multiplication over a galois field
    // Permutation part in the SPN(substitution-Permutation Network), in this case matrix multiplication
    unsigned char u;
    unsigned char v;

    for(int i=0; i<16; i+=4){
        u =z_time(z_time(a[i]^ a[i+2]));
        v= z_time(z_time(a[i+1]^ a[i+3]));
        a[i] ^= u;
	    a[i+1] ^= v;
	    a[i+2] ^= u;
	    a[i+3] ^= v; 
    }
	
    mix_columns(a);    
    };

unsigned char row2columns(unsigned char *round_key){
    //turning the inputted row wise array and making it into a column wise array
    unsigned char column_1[]= {round_key[0], round_key[4], round_key[8], round_key[12]};
    unsigned char column_2[]= {round_key[1], round_key[5], round_key[9], round_key[13]};
    unsigned char column_3[]= {round_key[2], round_key[6], round_key[10], round_key[14]};
    unsigned char column_4[]= {round_key[3], round_key[7], round_key[11], round_key[15]};
    for(int i=0; i<4;i++){
        round_key[i]= column_1[i];
    }
    for(int i=4; i<8;i++){
        round_key[i]= column_1[i];
    }
    for(int i=8; i<12;i++){
        round_key[i]= column_1[i];
    }
    for(int i=12; i<16;i++){
        round_key[i]= column_1[i];
    }
}


void add_round_key( unsigned char *plaintext, unsigned char *cipher_key ){
    //adding round key by XOR
    for(int i=0; i<16; i++){
       plaintext[i] ^= cipher_key[i];
    }
};

unsigned char key_schedule(unsigned char *cipher_key, unsigned char *round_key){
    //128-bit key

    //giving the round key the values from the cipher key as their base
    for(int i=0; i<16; i++){
        round_key[i]= cipher_key[i];
    }
    //making the round key column wise instead of row wise
    row2columns(round_key);
    
    //round 1
    //step 1- take the last columns and rotword(rotate word) operation on it, rotating by just 1 byte, moves the first character to the last
    unsigned char temp, temp2;
    temp = round_key[15];
    round_key[15]= round_key[12];
    round_key[12]= round_key[13];
    round_key[13]= round_key[14];
    round_key[14]= temp;

    //step 2- apply sub_bytes step
    for (int i=12; i<16; i++){
        round_key[i]= sub_box[ round_key[i] ];
    };
    
    unsigned char rcon_column[]= {rcon[0], rcon[10], rcon[20], rcon[30]};
    //step 3- take the first column, XOR that with the rotworded&sub_byted column and XOR with RCON table 
   for(int i=0; i<4; i++){
       round_key[i]^= round_key[i+12] ^ rcon_column[i];
    }
    
    row2columns(cipher_key);
    //step 4- take this new column and XOR it with the second column of the inputted cipher cipher_key
    for(int i=4; i<16; i++){
       round_key[i] = round_key[i-4] ^ cipher_key[i];
    }

    //round 2
    round_key[16]= round_key[13] ;
    round_key[17]= round_key[14];
    round_key[18]= round_key[15];
    round_key[19]= round_key[12];

    //step 2
    for (int i=16; i<20; i++){
        round_key[i]= sub_box[ round_key[i] ];
    };  

     unsigned char rcon_column2[]= {rcon[1], rcon[11], rcon[21], rcon[31]};
    //step 3
   for(int i=16; i<20; i++){
       round_key[i]= round_key[i]^ round_key[i-16] ^ rcon_column2[i-16];
    }

    //step 4
    for(int i=20; i<32; i++){
       round_key[i] = round_key[i-4] ^ round_key[i-16];
    }

    //round 3
    round_key[32]= round_key[29] ;
    round_key[33]= round_key[30];
    round_key[34]= round_key[31];
    round_key[35]= round_key[28];

    //step 2
    for (int i=32; i<36; i++){
        round_key[i]= sub_box[ round_key[i] ];
    };  

     unsigned char rcon_column3[]= {rcon[2], rcon[12], rcon[22], rcon[32]};
    //step 3
   for(int i=32; i<36; i++){
       round_key[i]= round_key[i]^ round_key[i-16] ^ rcon_column3[i-32];
    }

    //step 4
    for(int i=36; i<48; i++){
       round_key[i] = round_key[i-4] ^ round_key[i-16];
    }


    //round 4
    round_key[48]= round_key[45] ;
    round_key[49]= round_key[46];
    round_key[50]= round_key[47];
    round_key[51]= round_key[44];

    //step 2
    for (int i=48; i<52; i++){
        round_key[i]= sub_box[ round_key[i] ];
    };  

     unsigned char rcon_column4[]= {rcon[3], rcon[13], rcon[23], rcon[33]};
    //step 3
   for(int i=48; i<52; i++){
       round_key[i]= round_key[i]^ round_key[i-16] ^ rcon_column4[i-48];
    }

    //step 4
    for(int i=52; i<64; i++){
       round_key[i] = round_key[i-4] ^ round_key[i-16];
    }

    //round 5
    round_key[64]= round_key[61] ;
    round_key[65]= round_key[62];
    round_key[66]= round_key[63];
    round_key[67]= round_key[60];

    //step 2
    for (int i=64; i<68; i++){
        round_key[i]= sub_box[ round_key[i] ];
    };  

     unsigned char rcon_column5[]= {rcon[4], rcon[14], rcon[24], rcon[34]};
    //step 3
   for(int i=64; i<68; i++){
       round_key[i]= round_key[i]^ round_key[i-16] ^ rcon_column5[i-64];
    }

    //step 4
    for(int i=68; i<80; i++){
       round_key[i] = round_key[i-4] ^ round_key[i-16];
    }
    
    //round 6
    round_key[80]= round_key[77] ;
    round_key[81]= round_key[78];
    round_key[82]= round_key[79];
    round_key[83]= round_key[76];

    for (int i=80; i<84; i++){
        round_key[i]= sub_box[ round_key[i] ];
    }

     unsigned char rcon_column6[]= {rcon[5], rcon[15], rcon[25], rcon[35]};
    //step 3
   for(int i=80; i<84; i++){
       round_key[i]= round_key[i]^ round_key[i-16] ^ rcon_column6[i-80];
    }

    //step 4
    for(int i=84; i<96; i++){
       round_key[i] = round_key[i-4] ^ round_key[i-16];
    }

    //round 7
    round_key[96]= round_key[93] ;
    round_key[97]= round_key[94];
    round_key[98]= round_key[95];
    round_key[99]= round_key[92];

    //step 2
    for (int i=96; i<100; i++){
        round_key[i]= sub_box[ round_key[i] ];
    }

     unsigned char rcon_column7[]= {rcon[6], rcon[16], rcon[26], rcon[36]};
    //step 3
   for(int i=96; i<100; i++){
       round_key[i]= round_key[i]^ round_key[i-16] ^ rcon_column7[i-96];
    }

    //step 4
    for(int i=100; i<112; i++){
       round_key[i] = round_key[i-4] ^ round_key[i-16];
    }

    //round 8
    round_key[112]= round_key[109] ;
    round_key[113]= round_key[110];
    round_key[114]= round_key[111];
    round_key[115]= round_key[108];

    //step 2
    for (int i=112; i<116; i++){
        round_key[i]= sub_box[ round_key[i] ];
    }

     unsigned char rcon_column8[]= {rcon[7], rcon[17], rcon[27], rcon[37]};
    //step 3 
   for(int i=112; i<116; i++){
       round_key[i]= round_key[i]^ round_key[i-16] ^ rcon_column8[i-112];
    }

    //step 4
    for(int i=116; i<128; i++){
       round_key[i] = round_key[i-4] ^ round_key[i-16];
    }

    //round 9
    round_key[128]= round_key[125] ;
    round_key[129]= round_key[126];
    round_key[130]= round_key[127];
    round_key[131]= round_key[124];

    //step 2
    for (int i=128; i<132; i++){
        round_key[i]= sub_box[ round_key[i] ];
    }

     unsigned char rcon_column9[]= {rcon[8], rcon[18], rcon[28], rcon[38]};
    //step 3
   for(int i=128; i<132; i++){
       round_key[i]= round_key[i]^ round_key[i-16] ^ rcon_column9[i-128];
    }

    //step 4
    for(int i=132; i<144; i++){
       round_key[i] = round_key[i-4] ^ round_key[i-16];
    }

    //round 10
    round_key[144]= round_key[141] ;
    round_key[145]= round_key[142];
    round_key[146]= round_key[143];
    round_key[147]= round_key[140];

    //step 2
    for (int i=144; i<148; i++){
        round_key[i]= sub_box[ round_key[i] ];
    }

     unsigned char rcon_column10[]= {rcon[9], rcon[19], rcon[29], rcon[39]};
    //step 3
   for(int i=144; i<148; i++){
       round_key[i]= round_key[i]^ round_key[i-16] ^ rcon_column10[i-144];
    }

    //step 4
    for(int i=148; i<160; i++){
       round_key[i] = round_key[i-4] ^ round_key[i-16];
    }

};

void encrypt_block(unsigned char *plaintext, unsigned char *cipher_key, unsigned char *round_key){
    // Rijndael algorithm with 128-bit plaintext to ciphertext
    // switching plaintext from row wise to column wise
    row2columns(plaintext);
    //initial round - round key stage
    add_round_key( plaintext, cipher_key);

    // 9 main rounds
    for(int i=0;i<144;i+=16)
    { 
    sub_bytes( plaintext);
    shift_rows( plaintext);
    mix_columns( plaintext);
    add_round_key( plaintext, &round_key[i]);
   }
   //final round
    sub_bytes( plaintext);
    shift_rows( plaintext);
    add_round_key( plaintext, &round_key[144]);
} 
  

void decrypt_block(unsigned char *cipher_key, unsigned char *ciphertext, unsigned char *round_key){
    //Rijndael algorithm ciphertext to plaintext 

    //initial round- opposite of encrypt
    add_round_key( ciphertext, &round_key[144]);
    invert_shift_rows( ciphertext);
    invert_sub_bytes( ciphertext);
    
    //9 main rounds
    for(int i=128;i>-16;i-=16)
    { 
    //printf("%x\n", round_key[i]);
    add_round_key( ciphertext, &round_key[i]);
    inv_mix_column( ciphertext);
    invert_shift_rows( ciphertext);
    invert_sub_bytes( ciphertext);
   }
   //final round (first round in encrypt)
   add_round_key( ciphertext, cipher_key);
} 

