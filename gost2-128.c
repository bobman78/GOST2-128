/*
 * GOST2-128 Cipher
 * GOST2-128 by Alexander Pukall 2016
 * 
 * Based on the 25 Movember 1993 draft translation
 * by Aleksandr Malchik, with Whitfield Diffie, of the Government
 * Standard of the U.S.S.R. GOST 28149-89, "Cryptographic Transformation
 * Algorithm", effective 1 July 1990.  
 * 
 * 4096-bit keys with 64 * 64-bit subkeys
 * 
 * 128-bit block cipher (like AES) 64 rounds
 * 
 * Uses MD2II hash function to create the 64 subkeys
 * 
 * Code free for all, even for commercial software 
 * No restriction to use. Public Domain 
 * 
 * Compile with gcc: gcc gost2-128.c -o gost2-128
 * 
 */

#include <stdint.h>
#include <string.h>
#include <stdio.h>

typedef uint64_t word64;

#define n1 512 /* 4096-bit GOST2-128 key for 64 * 64-bit subkeys */


int x1,x2,i;
unsigned char h2[n1];
unsigned char h1[n1*3];


static void init()
{
    
   x1 = 0;
   x2 = 0;
    for (i = 0; i < n1; i++)
        h2[i] = 0;
    for (i = 0; i < n1; i++)
        h1[i] = 0;
}

static void hashing(unsigned char t1[], size_t b6)
{
    static unsigned char s4[256] = 
    {   13, 199,  11,  67, 237, 193, 164,  77, 115, 184, 141, 222,  73,
        38, 147,  36, 150,  87,  21, 104,  12,  61, 156, 101, 111, 145,
       119,  22, 207,  35, 198,  37, 171, 167,  80,  30, 219,  28, 213,
       121,  86,  29, 214, 242,   6,   4,  89, 162, 110, 175,  19, 157,
         3,  88, 234,  94, 144, 118, 159, 239, 100,  17, 182, 173, 238,
        68,  16,  79, 132,  54, 163,  52,   9,  58,  57,  55, 229, 192,
       170, 226,  56, 231, 187, 158,  70, 224, 233, 245,  26,  47,  32,
        44, 247,   8, 251,  20, 197, 185, 109, 153, 204, 218,  93, 178,
       212, 137,  84, 174,  24, 120, 130, 149,  72, 180, 181, 208, 255,
       189, 152,  18, 143, 176,  60, 249,  27, 227, 128, 139, 243, 253,
        59, 123, 172, 108, 211,  96, 138,  10, 215,  42, 225,  40,  81,
        65,  90,  25,  98, 126, 154,  64, 124, 116, 122,   5,   1, 168,
        83, 190, 131, 191, 244, 240, 235, 177, 155, 228, 125,  66,  43,
       201, 248, 220, 129, 188, 230,  62,  75,  71,  78,  34,  31, 216,
       254, 136,  91, 114, 106,  46, 217, 196,  92, 151, 209, 133,  51,
       236,  33, 252, 127, 179,  69,   7, 183, 105, 146,  97,  39,  15,
       205, 112, 200, 166, 223,  45,  48, 246, 186,  41, 148, 140, 107,
        76,  85,  95, 194, 142,  50,  49, 134,  23, 135, 169, 221, 210,
       203,  63, 165,  82, 161, 202,  53,  14, 206, 232, 103, 102, 195,
       117, 250,  99,   0,  74, 160, 241,   2, 113};
       
    int b1,b2,b3,b4,b5;
   
	b4=0;
    while (b6) {
    
        for (; b6 && x2 < n1; b6--, x2++) {
            b5 = t1[b4++];
            h1[x2 + n1] = b5;
            h1[x2 + (n1*2)] = b5 ^ h1[x2];

            x1 = h2[x2] ^= s4[b5 ^ x1];
        }

        if (x2 == n1)
        {
            b2 = 0;
            x2 = 0;
            
            for (b3 = 0; b3 < (n1+2); b3++) {
                for (b1 = 0; b1 < (n1*3); b1++)
                    b2 = h1[b1] ^= s4[b2];
                b2 = (b2 + b3) % 256;
            }
           }
          }
        }

static void end(unsigned char h4[n1])
{
    
    unsigned char h3[n1];
    int i, n4;
    
    n4 = n1 - x2;
    for (i = 0; i < n4; i++) h3[i] = n4;
    hashing(h3, n4);
    hashing(h2, sizeof(h2));
    for (i = 0; i < n1; i++) h4[i] = h1[i];
}


/* create 64 * 64-bit subkeys from h4 hash */
void create_keys(unsigned char h4[n1],word64 key[64])
{

  int k=0;
  for (int i=0;i<64;i++)
   {
       for (int z=0;z<8;z++) key[i]=(key[i]<<8)+(h4[k++]&0xff);
   }
   
}
 	
static unsigned char const k1[16] = {
	0x4,0xA,0x9,0x2,0xD,0x8,0x0,0xE,0x6,0xB,0x1,0xC,0x7,0xF,0x5,0x3 };
static unsigned char const k2[16] = {
	0xE,0xB,0x4,0xC,0x6,0xD,0xF,0xA,0x2,0x3,0x8,0x1,0x0,0x7,0x5,0x9 };
static unsigned char const k3[16] = {
	0x5,0x8,0x1,0xD,0xA,0x3,0x4,0x2,0xE,0xF,0xC,0x7,0x6,0x0,0x9,0xB };
static unsigned char const k4[16] = {
	0x7,0xD,0xA,0x1,0x0,0x8,0x9,0xF,0xE,0x4,0x6,0xC,0xB,0x2,0x5,0x3 };
static unsigned char const k5[16] = {
	0x6,0xC,0x7,0x1,0x5,0xF,0xD,0x8,0x4,0xA,0x9,0xE,0x0,0x3,0xB,0x2 };
static unsigned char const k6[16] = {
	0x4,0xB,0xA,0x0,0x7,0x2,0x1,0xD,0x3,0x6,0x8,0x5,0x9,0xC,0xF,0xE };
static unsigned char const k7[16] = {
	0xD,0xB,0x4,0x1,0x3,0xF,0x5,0x9,0x0,0xA,0xE,0x7,0x6,0x8,0x2,0xC };
static unsigned char const k8[16] = {
	0x1,0xF,0xD,0x0,0x5,0x7,0xA,0x4,0x9,0x2,0x3,0xE,0x6,0xB,0x8,0xC }; 						

static unsigned char const k9[16] = {
	0xC,0x4,0x6,0x2,0xA,0x5,0xB,0x9,0xE,0x8,0xD,0x7,0x0,0x3,0xF,0x1 };
static unsigned char const k10[16] = {
	0x6,0x8,0x2,0x3,0x9,0xA,0x5,0xC,0x1,0xE,0x4,0x7,0xB,0xD,0x0,0xF };
static unsigned char const k11[16] = {
	0xB,0x3,0x5,0x8,0x2,0xF,0xA,0xD,0xE,0x1,0x7,0x4,0xC,0x9,0x6,0x0 };
static unsigned char const k12[16] = {
	0xC,0x8,0x2,0x1,0xD,0x4,0xF,0x6,0x7,0x0,0xA,0x5,0x3,0xE,0x9,0xB };
static unsigned char const k13[16] = {
	0x7,0xF,0x5,0xA,0x8,0x1,0x6,0xD,0x0,0x9,0x3,0xE,0xB,0x4,0x2,0xC };
static unsigned char const k14[16] = {
	0x5,0xD,0xF,0x6,0x9,0x2,0xC,0xA,0xB,0x7,0x8,0x1,0x4,0x3,0xE,0x0 };
static unsigned char const k15[16] = {
	0x8,0xE,0x2,0x5,0x6,0x9,0x1,0xC,0xF,0x4,0xB,0x0,0xD,0xA,0x3,0x7 };				
static unsigned char const k16[16] = {
	0x1,0x7,0xE,0xD,0x0,0x5,0x8,0x3,0x4,0xF,0xA,0x6,0x9,0xC,0xB,0x2 }; 

/* Byte-at-a-time substitution boxes */
static unsigned char k175[256];
static unsigned char k153[256];
static unsigned char k131[256];
static unsigned char k109[256];
static unsigned char k87[256];
static unsigned char k65[256];
static unsigned char k43[256];
static unsigned char k21[256];

/*
 * Build byte-at-a-time subtitution tables.
 * This must be called once for global setup.
 */
void
kboxinit(void)
{
	int i;
	for (i = 0; i < 256; i++) {
		
		k175[i] = k16[i >> 4] << 4 | k15[i & 15];
		k153[i] = k14[i >> 4] << 4 | k13[i & 15];
		k131[i] = k12[i >> 4] << 4 | k11[i & 15];
		k109[i] = k10[i >> 4] << 4 | k9[i & 15];

		k87[i] = k8[i >> 4] << 4 | k7[i & 15];
		k65[i] = k6[i >> 4] << 4 | k5[i & 15];
		k43[i] = k4[i >> 4] << 4 | k3[i & 15];
		k21[i] = k2[i >> 4] << 4 | k1[i & 15];
	}

}

/* #define TEST */

#if __GNUC__
__inline__
#endif
static word64
f(word64 x)
{
	/* Do substitutions */
	word64 y,z;

	y = x >> 32;
	z = x & 0xffffffff;

#ifdef TEST
	/* This is annoyingly slow */
	y = k8[y>>28 & 15] << 28 | k7[y>>24 & 15] << 24 |
	    k6[y>>20 & 15] << 20 | k5[y>>16 & 15] << 16 |
	    k4[y>>12 & 15] << 12 | k3[y>> 8 & 15] <<  8 |
	    k2[y>> 4 & 15] <<  4 | k1[y     & 15];
	
	z = k16[z>>28 & 15] << 28 | k15[z>>24 & 15] << 24 |
	    k14[z>>20 & 15] << 20 | k13[z>>16 & 15] << 16 |
	    k12[z>>12 & 15] << 12 | k11[z>> 8 & 15] <<  8 |
	    k10[z>> 4 & 15] <<  4 | k9[z     & 15];
	
	x = y << 32;
	x = x | (z & 0xffffffff);

	
#else
	/* This is faster */
	y = k87[y>>24 & 255] << 24 | k65[y>>16 & 255] << 16 |
	    k43[y>> 8 & 255] <<  8 | k21[y & 255];
	    
	z = k175[z>>24 & 255] << 24 | k153[z>>16 & 255] << 16 |
	    k131[z>> 8 & 255] <<  8 | k109[z & 255];

    x = y << 32;
    x = x | (z & 0xffffffff);
		
#endif
   
	/* Rotate left 11 bits */
	return (x<<11) | (x>>(64-11));
	
}

void gostcrypt(word64 const in[2], word64 out[2], word64 key[64])
{
	register word64 ngost1, ngost2; 

	ngost1 = in[0];
	ngost2 = in[1];

	/* Instead of swapping halves, swap names each round */
	
	int k=0;
	
	for (int i=0;i<32;i++)
	{
	    ngost2 ^= f(ngost1+key[k++]);
	    ngost1 ^= f(ngost2+key[k++]);
	    
	}	
	
	/* There is no swap after the last round */
	out[0] = ngost2;
	out[1] = ngost1;
}
	
void gostdecrypt(word64 const in[2], word64 out[2], word64 key[64])
{
	register word64 ngost1, ngost2; 

	ngost1 = in[0];
	ngost2 = in[1];
	
	int k=63;
	
	for (int i=0;i<32;i++)
	{
	    ngost2 ^= f(ngost1+key[k--]);
	    ngost1 ^= f(ngost2+key[k--]);
	}	

	out[0] = ngost2;
	out[1] = ngost1;
}

int main(void)
{
	unsigned char text[33]; /* up to 256 chars for the password */
                                /* password can be hexadecimal */
	word64 key[64];
	word64 plain[2];
	word64 cipher[2];
	word64 decrypted[2];
	
	unsigned char h4[n1];

	kboxinit();

  printf("GOST2-128 by Alexander PUKALL 2016 \n 128-bit block 4096-bit subkeys 64 rounds\n");
  printf("Code can be freely use even for commercial software\n");
  printf("Based on GOST 28147-89 by Aleksandr Malchik with Whitfield Diffie\n\n");

    /* The key creation procedure is slow, it only needs to be done once */
    /* as long as the user does not change the key. You can encrypt and decrypt */
    /* as many blocks as you want without having to hash the key again. */
    /* kboxinit(); -> only once */
    /* init(); hashing(text,length);  end(h4); -> only once */
    /* create_keys(h4,key); -> only once too */
    

    /* EXAMPLE 1 */
    
    init();

    strcpy((char *) text,"My secret password!0123456789abc");

    hashing(text, 32);
    end(h4); /* h4 = 4096-bit key from hash "My secret password!0123456789abc */
   
    create_keys(h4,key); /* create 64 * 64-bit subkeys from h4 hash */
  
    plain[0] = 0xFEFEFEFEFEFEFEFE; /* 0xFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE GOST2-128 block plaintext */
    plain[1] = 0xFEFEFEFEFEFEFEFE;
    
    printf("Key 1:%s\n",text);
    printf ("Plaintext  1: %0.16llX%0.16llX\n", plain[0], plain[1]);
    
    gostcrypt(plain, cipher, key);
        
    printf ("Encryption 1: %0.16llX%0.16llX\n", cipher[0],cipher[1]);
       
    gostdecrypt(cipher, decrypted, key);
    
    printf ("Decryption 1: %0.16llX%0.16llX\n\n", decrypted[0], decrypted[1]);

    /* EXAMPLE 2 */
    
    init();

    strcpy((char *) text,"My secret password!0123456789ABC");

    hashing(text, 32);
    end(h4); /* h4 = 4096-bit key from hash "My secret password!0123456789ABC */
   
    create_keys(h4,key); /* create 64 * 64-bit subkeys from h4 hash */
  
    plain[0] = 0x0000000000000000; /* 0x00000000000000000000000000000000 GOST2-128 block plaintext */
    plain[1] = 0x0000000000000000;
    
    printf("Key 2:%s\n",text);
    printf ("Plaintext  2: %0.16llX%0.16llX\n", plain[0], plain[1]);
    
    gostcrypt(plain, cipher, key);
        
    printf ("Encryption 2: %0.16llX%0.16llX\n", cipher[0],cipher[1]);
       
    gostdecrypt(cipher, decrypted, key);
    
    printf ("Decryption 2: %0.16llX%0.16llX\n\n", decrypted[0], decrypted[1]);
			   
    /* EXAMPLE 3 */
    
    init();

    strcpy((char *) text,"My secret password!0123456789abZ");

    hashing(text, 32);
    end(h4); /* h4 = 4096-bit key from hash "My secret password!0123456789abZ */
   
    create_keys(h4,key); /* create 64 * 64-bit subkeys from h4 hash */
  
    plain[0] = 0x0000000000000000; /* 0x00000000000000000000000000000001 GOST2-128 block plaintext */
    plain[1] = 0x0000000000000001;
    
    printf("Key 3:%s\n",text);
    printf ("Plaintext  3: %0.16llX%0.16llX\n", plain[0], plain[1]);
    
    gostcrypt(plain, cipher, key);
        
    printf ("Encryption 3: %0.16llX%0.16llX\n", cipher[0],cipher[1]);
       
    gostdecrypt(cipher, decrypted, key);
    
    printf ("Decryption 3: %0.16llX%0.16llX\n\n", decrypted[0], decrypted[1]);
    
    return(0);
}

/*
 
Key 1:My secret password!0123456789abc
Plaintext  1: FEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE
Encryption 1: 8CA4C196B773D9C9A00AD3931F9B2B09
Decryption 1: FEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE

Key 2:My secret password!0123456789ABC
Plaintext  2: 00000000000000000000000000000000
Encryption 2: 96AB544910861D5B22B04FC984D80098
Decryption 2: 00000000000000000000000000000000

Key 3:My secret password!0123456789abZ
Plaintext  3: 00000000000000000000000000000001
Encryption 3: ACF914AC22AE2079390BC240ED51916F
Decryption 3: 00000000000000000000000000000001

*/
