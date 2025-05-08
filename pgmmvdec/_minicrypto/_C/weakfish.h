/*
 * Implementation of PGMMV special key schedule algorithm,
 * Version 0.1.
 * Copyright (c) 2024 by Gee Wang.
 *
 * See the weakfish.c file for the details of the how and why of this code.
 *
 * The author hereby grants a perpetual license to everybody to
 * use this code for any purpose as long as the copyright message is included
 * in the source code of this or any derived work.
 */

#include <stdint.h>

/*
 * PLATFORM FIXES
 * ==============
 *
 * The following definitions have to be fixed for each particular platform
 * you work on. If you have a multi-platform program, you no doubt have
 * portable definitions that you can substitute here without changing
 * the rest of the code.
 *
 * The defaults provided here should work on most PC compilers.
 */


/*
 * A Weakfish_Byte must be an unsigned 8-bit integer.
 * It must also be the elementary data size of your C platform,
 * i.e. sizeof( Weakfish_Byte ) == 1.
 */
typedef uint8_t     Weakfish_Byte;

/*
 * A Weakfish_UInt32 must be an unsigned integer of at least 32 bits.
 */
typedef uint32_t    Weakfish_UInt32;


/*
 * END OF PLATFORM FIXES
 * =====================
 *
 * You should not have to touch the rest of this file, but the code
 * in weakfish.c has a few things you need to fix too.
 */


/*
 * Test the Weakfish implementation.
 *
 * This function SHOULD be called before any other function in the
 * Weakfish implementation is called.
 * It only needs to be called once.
 *
 * If the Weakfish_fatal function is not called, the code passed the test.
 * (See the weakfish.c file for details on the Weakfish_fatal function.)
 */
extern void Weakfish_selftest();


/*
 * Encrypt a single block of data.
 *
 * This function encrypts a single block of 16 bytes of data.
 * If you want to encrypt a larger or variable-length message,
 * you will have to use a cipher mode, such as CBC or CTR.
 * These are outside the scope of this implementation.
 *
 * Arguments:
 * p        Plaintext to be encrypted
 * c        Place to store the ciphertext
 */
extern void Weakfish_encrypt(
    Weakfish_Byte p[16],
    Weakfish_Byte c[16]
);


/*
 * Decrypt a single block of data.
 *
 * This function decrypts a single block of 16 bytes of data.
 * If you want to decrypt a larger or variable-length message,
 * you will have to use a cipher mode, such as CBC or CTR.
 * These are outside the scope of this implementation.
 *
 * Arguments:
 * c        Ciphertext to be decrypted
 * p        Place to store the plaintext
 */
extern void Weakfish_decrypt(
    Weakfish_Byte c[16],
    Weakfish_Byte p[16]
);
