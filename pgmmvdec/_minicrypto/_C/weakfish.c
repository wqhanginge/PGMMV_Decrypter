/*
 * Implementation of PGMMV special key schedule algorithm,
 * Version 0.1.
 * Copyright (c) 2024 by Gee Wang.
 * (See further down for the almost-unrestricted licensing terms.)
 *
 * --------------------------------------------------------------------------
 * There are two files for this implementation:
 * - weakfish.h, the header file.
 * - weakfish.c, the code file.
 *
 * To incorporate this code into your program you should:
 * - Check the licensing terms further down in this comment.
 * - Fix the two type definitions in weakfish.h to suit your platform.
 * - Fix a few definitions in weakfish.c in the section marked
 *   PLATFORM FIXES. There is one important ones that affects
 *   functionality, and then a few definitions that you can optimise
 *   for efficiency but those have no effect on the functionality.
 *   Don't change anything else.
 * - Put the code in your project and compile it.
 *
 * To use this library you should:
 * - Call Weakfish_selftest() in your program before any other function in
 *   this library.
 * - Use Weakfish_encrypt(...) and Weakfish_decrypt(...) to encrypt and decrypt
 *   data.
 * See the comments in the header file for details on these functions.
 * --------------------------------------------------------------------------
 *
 * This special key schedule algorithm is derived from Pixel Game Maker MV
 * and is used in the encryption and decryption process when a weak key
 * is provided. The algorithm was proposed by blluv, and this is the C
 * implementation to provide a fast and portable version. You can find the
 * algorithm author blluv at
 *    https://github.com/blluv/
 *
 * This implementation draws heavily from the Twofish implementation by
 * Niels Ferguson. Most of the code was copied from his work. Additionally,
 * this implementation uses the same license. You might get the latest
 * version of his work at
 *    http://niels.ferguson.net/
 *
 * Many thanks to blluv and Niels.
 *
 * Now for the license:
 * The author hereby grants a perpetual license to everybody to
 * use this code for any purpose as long as the copyright message is included
 * in the source code of this or any derived work.
 *
 * Yes, this means that you, your company, your club, and anyone else
 * can use this code anywhere you want. You can change it and distribute it
 * under the GPL, include it in your commercial product without releasing
 * the source code, put it on the web, etc.
 * The only thing you cannot do is remove my copyright message,
 * or distribute any source code based on this implementation that does not
 * include my copyright message.
 */

/*
 * DISCLAIMER: As I'm giving away my work for free, I'm of course not going
 * to accept any liability of any form. This code, or the Weakfish cipher,
 * might very well be flawed; you have been warned.
 * This software is provided as-is, without any kind of warrenty or
 * guarantee. And that is really all you can expect when you download
 * code for free from the Internet.
 */

/*
 * Version history:
 * Version 0.1, 2024-10-02
 *      First written.
 */


/*
 * Minimum set of include files.
 * You should not need any application-specific include files for this code.
 * In fact, adding you own header files could break one of the many macros or
 * functions in this file. Be very careful.
 * Standard include files will probably be ok.
 */
#include <string.h>     /* for memcmp() */
#include "weakfish.h"


/*
 * PLATFORM FIXES
 * ==============
 *
 * Fix the type definitions in weakfish.h first!
 *
 * The following definitions have to be fixed for each particular platform
 * you work on. If you have a multi-platform program, you no doubt have
 * portable definitions that you can substitute here without changing the
 * rest of the code.
 */


/*
 * Function called if something is fatally wrong with the implementation.
 * This fatal function is called when a coding error is detected in the
 * Weakfish implementation, or when somebody passes an obviously erroneous
 * parameter to this implementation. There is not much you can do when
 * the code contains bugs, so we just stop.
 *
 * The argument is a string. Ideally the fatal function prints this string
 * as an error message. Whatever else this function does, it should never
 * return. A typical implementation would stop the program completely after
 * printing the error message.
 *
 * This default implementation is not very useful,
 * but does not assume anything about your environment.
 * It will at least let you know something is wrong....
 * I didn't want to include any libraries to print and error or so,
 * as this makes the code much harder to integrate in a project.
 *
 * Note that the Weakfish_fatal function may not return to the caller.
 * Unfortunately this is not something the self-test can test for,
 * so you have to make sure of this yourself.
 *
 * If you want to call an external function, be careful about including
 * your own header files here. This code uses a lot of macros, and your
 * header file could easily break it. Maybe the best solution is to use
 * a separate extern statement for your fatal function.
 */
//#define Weakfish_fatal( msg )       {for(;;);}
#include "fatal.h"
#define Weakfish_fatal( msg )       { cipher_fatal(msg); }


/*
 * The rest of the settings are not important for the functionality
 * of this Weakfish implementation. That is, their default settings
 * work on all platforms. You can change them to improve the
 * speed of the implementation on your platform. Erroneous settings
 * will result in erroneous implementations, but the self-test should
 * catch those.
 */


/*
 * Macros to rotate a Weakfish_UInt32 value left or right by the
 * specified number of bits. This should be a 32-bit rotation,
 * and not rotation of, say, 64-bit values.
 *
 * Every encryption or decryption operation uses 32 of these rotations,
 * so it is a good idea to make these macros efficient.
 *
 * This fully portable definition has one piece of tricky stuff.
 * The UInt32 might be larger than 32 bits, so we have to mask
 * any higher bits off. The simplest way to do this is to 'and' the
 * value first with 0xffffffff and then shift it right. An optimising
 * compiler that has a 32-bit type can optimise this 'and' away.
 *
 * Unfortunately there is no portable way of writing the constant
 * 0xffffffff. You don't know which suffix to use (U, or UL?)
 * The UINT32_MASK definition uses a bit of trickery. Shift-left
 * is only defined if the shift amount is strictly less than the size
 * of the UInt32, so we can't use (1<<32). The answer is to take the value
 * 2, cast it to a UInt32, shift it left 31 positions, and subtract one.
 * Another example of how to make something very simple extremely difficult.
 *
 * The rotation macros are straightforward.
 * They are only applied to UInt32 values, which are _unsigned_
 * so the >> operator must do a logical shift that brings in zeroes.
 * On most platforms you will only need to optimise the ROL32 macro; the
 * ROR32 macro is not inefficient on an optimising compiler as all rotation
 * amounts in this code are known at compile time.
 *
 * On many platforms there is a faster solution.
 * For example, MS compilers have the __rotl and __rotr functions
 * that generate x86 rotation instructions.
 */
#define UINT32_MASK    ( (((UInt32)2)<<31) - 1 )
#define ROL32( x, n )  ( (x)<<(n) | ((x) & UINT32_MASK) >> (32-(n)) )
#define ROR32( x, n )  ROL32( (x), 32-(n) )


/*
 * Method used to read the input and write the output.
 * WARNING: non-portable code if set; might not work on all platforms.
 *
 * Weakfish operates on 32-bit words. The input to the cipher is
 * a byte array, as is the output. The portable method of doing the
 * conversion is a bunch of rotate and mask operations, but on many
 * platforms it can be done faster using a cast.
 * This only works if your CPU allows UInt32 accesses to arbitrary Byte
 * addresses.
 *
 * Set to 0 to use the shift and mask operations. This is fully
 * portable. .
 *
 * Set to 1 to use a cast. The Byte * is cast to a UInt32 *, and a
 * UInt32 is read. If necessary (as indicated by the CPU_IS_BIG_ENDIAN
 * macro) the byte order in the UInt32 is swapped. The reverse is done
 * to write the output of the encryption/decryption. Make sure you set
 * the CPU_IS_BIG_ENDIAN flag appropriately.
 * This option does not work unless a UInt32 is exactly 32 bits.
 *
 * This macro only changes the reading/writing of the plaintext/ciphertext.
 */
#define CONVERT_USING_CASTS    0    /* default = 0 */


/*
 * Endianness switch.
 * Only relevant if CONVERT_USING_CASTS is set.
 *
 * Set to 1 on a big-endian machine, and to 0 on a little-endian machine.
 * Weakfish uses the little-endian convention (least significant byte first)
 * and big-endian machines (using most significant byte first)
 * have to do a few conversions.
 *
 * CAUTION: This code has never been tested on a big-endian machine,
 * because I don't have access to one. Feedback appreciated.
 */
#define CPU_IS_BIG_ENDIAN    0


/*
 * Macro to reverse the order of the bytes in a UInt32.
 * Used to convert to little-endian on big-endian machines.
 * This macro is always tested, but only used in the encryption and
 * decryption if CONVERT_USING_CASTS, and CPU_IS_BIG_ENDIAN
 * are both set. In other words: this macro is only speed-critical if
 * both these flags have been set.
 *
 * This default definition of SWAP works, but on many platforms there is a
 * more efficient implementation.
 */
#define BSWAP(x) ((ROL32((x),8) & 0x00ff00ff) | (ROR32((x),8) & 0xff00ff00))


/*
 * END OF PLATFORM FIXES
 * =====================
 *
 * You should not have to touch the rest of this file.
 */


/*
 * Convert the external type names to some that are easier to use inside
 * this file. I didn't want to use the names Byte and UInt32 in the
 * header file, because many programs already define them and using two
 * conventions at once can be very difficult.
 * Don't change these definitions! Change the originals
 * in weakfish.h instead.
 */
/* A Byte must be an unsigned integer, 8 bits long. */
typedef Weakfish_Byte   Byte;
/* A UInt32 must be an unsigned integer at least 32 bits long. */
typedef Weakfish_UInt32 UInt32;


/*
 * Define a macro ENDIAN_CONVERT.
 *
 * We define a macro ENDIAN_CONVERT that performs a BSWAP on big-endian
 * machines, and is the identity function on little-endian machines.
 * The code then uses this macro without considering the endianness.
 */
#if CPU_IS_BIG_ENDIAN
#define ENDIAN_CONVERT(x)    BSWAP(x)
#else
#define ENDIAN_CONVERT(x)    (x)
#endif


/*
 * We need macros to load and store UInt32 from/to byte arrays
 * using the least-significant-byte-first convention.
 *
 * GET32( p ) gets a UInt32 in lsb-first form from four bytes pointed to
 * by p.
 * PUT32( v, p ) writes the UInt32 value v at address p in lsb-first form.
 */
#if CONVERT_USING_CASTS

    /* Get UInt32 from four bytes pointed to by p. */
#define GET32( p )    ENDIAN_CONVERT( *((UInt32 *)(p)) )
    /* Put UInt32 into four bytes pointed to by p */
#define PUT32( v, p ) *((UInt32 *)(p)) = ENDIAN_CONVERT(v)

#else

    /* Get UInt32 from four bytes pointed to by p. */
#define GET32( p ) \
    ( \
      (UInt32)((p)[0])    \
    | (UInt32)((p)[1])<< 8\
    | (UInt32)((p)[2])<<16\
    | (UInt32)((p)[3])<<24\
    )
    /* Put UInt32 into four bytes pointed to by p */
#define PUT32( v, p ) \
    (p)[0] = (Byte)(((v)      ) & 0xff);\
    (p)[1] = (Byte)(((v) >>  8) & 0xff);\
    (p)[2] = (Byte)(((v) >> 16) & 0xff);\
    (p)[3] = (Byte)(((v) >> 24) & 0xff)

#endif


/*
 * Test the platform-specific macros.
 * This function tests the macros defined so far to make sure the
 * definitions are appropriate for this platform.
 * If you make any mistake in the platform configuration, this should detect
 * that and inform you what went wrong.
 * Somewhere, someday, this is going to save somebody a lot of time,
 * because misbehaving macros are hard to debug.
 */
static void test_platform()
{
    /* Buffer with test values. */
    Byte buf[] = { 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0 };
    UInt32 C;
    UInt32 x, y;
    int i;

    /*
     * Some sanity checks on the types that can't be done in compile time.
     * A smart compiler will just optimise these tests away.
     * The pre-processor doesn't understand different types, so we cannot
     * do these checks in compile-time.
     *
     * The first check in each case is to make sure the size is correct.
     * The second check is to ensure that it is an unsigned type.
     */
    if (((UInt32)((UInt32)1 << 31) == 0) || ((UInt32)-1 < 0))
    {
        Weakfish_fatal("Weakfish code: Weakfish_UInt32 type not suitable");
    }
    if ((sizeof(Byte) != 1) || ((Byte)-1 < 0))
    {
        Weakfish_fatal("Weakfish code: Weakfish_Byte type not suitable");
    }

    /*
     * Sanity-check the endianness conversions.
     * This is just an aid to find problems. If you do the endianness
     * conversion macros wrong you will fail the full cipher test,
     * but that does not help you find the error.
     * Always make it easy to find the bugs!
     *
     * Detail: There is no fully portable way of writing UInt32 constants,
     * as you don't know whether to use the U or UL suffix. Using only U you
     * might only be allowed 16-bit constants. Using UL you might get 64-bit
     * constants which cannot be stored in a UInt32 without warnings, and
     * which generally behave subtly different from a true UInt32.
     * As long as we're just comparing with the constant,
     * we can always use the UL suffix and at worst lose some efficiency.
     * I use a separate '32-bit constant' macro in most of my other code.
     *
     * Start with testing GET32. We test it on all positions modulo 4
     * to make sure we can handly any position of inputs. (Some CPUs
     * do not allow non-aligned accesses which we would do if you used
     * the CONVERT_USING_CASTS option.
     */
    if (GET32(buf) != 0x78563412UL || GET32(buf + 1) != 0x9a785634UL
        || GET32(buf + 2) != 0xbc9a7856UL || GET32(buf + 3) != 0xdebc9a78UL)
    {
        Weakfish_fatal("Weakfish code: GET32 not implemented properly");
    }

    /*
     * We can now use GET32 to test PUT32.
     * We don't test the shifted versions. If GET32 can do that then
     * so should PUT32.
     */
    C = GET32(buf);
    PUT32(3 * C, buf);
    if (GET32(buf) != 0x69029c36UL)
    {
        Weakfish_fatal("Weakfish code: PUT32 not implemented properly");
    }


    /* Test ROL and ROR */
    for (i = 1; i < 32; i++)
    {
        /* Just a simple test. */
        x = ROR32(C, i);
        y = ROL32(C, i);
        x ^= (C >> i) ^ (C << (32 - i));
        y ^= (C << i) ^ (C >> (32 - i));
        x |= y;
        /*
         * Now all we check is that x is zero in the least significant
         * 32 bits. Using the UL suffix is safe here, as it doesn't matter
         * if we get a larger type.
         */
        if ((x & 0xffffffffUL) != 0)
        {
            Weakfish_fatal("Weakfish ROL or ROR not properly defined.");
        }
    }

    /* Test the BSWAP macro */
    if ((BSWAP(C)) != 0x12345678UL)
    {
        /*
         * The BSWAP macro should always work, even if you are not using it.
         * A smart optimising compiler will just remove this entire test.
         */
        Weakfish_fatal("BSWAP not properly defined.");
    }
}


/*
 * Perform a single self test on a (plaintext,ciphertext) tuple.
 */
static void test_vector()
{
    static Byte p[] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    static Byte c[] = {
        0xDC, 0xBA, 0x98, 0xFE, 0x10, 0x76, 0x54, 0x32,
        0x23, 0x45, 0x67, 0x01, 0xEF, 0x89, 0xAB, 0xCD
    };

    Byte tmp[16];               /* scratch pad. */

    /* Encrypt and test */
    Weakfish_encrypt(p, tmp);
    if (memcmp(c, tmp, 16) != 0)
    {
        Weakfish_fatal("Weakfish encryption failure");
    }

    /* Decrypt and test */
    Weakfish_decrypt(c, tmp);
    if (memcmp(p, tmp, 16) != 0)
    {
        Weakfish_fatal("Weakfish decryption failure");
    }

    /* The test keys are not secret, so we don't need to wipe xkey. */
}


/*
 * Test the Weakfish implementation.
 *
 * This routine runs all the self tests, in order of importance.
 *
 * In almost all applications the cost of running the self tests during
 * initialisation is insignificant, especially
 * compared to the time it takes to load the application from disk.
 * If you are very pressed for initialisation performance,
 * you could remove some of the tests. Make sure you did run them
 * once in the software and hardware configuration you are using.
 */
void Weakfish_selftest()
{
    /* First test the various platform-specific definitions. */
    test_platform();

    /* And run some tests on the whole cipher. */
    test_vector();
}


/* Full encryption process */
#define ENCRYPT( A,B,C,D ) \
    A = ROR32(A,8); B = ROL32(B,8); \
    C = ROR32(C,8); D = ROL32(D,8)

/* Full decryption process */
#define DECRYPT( A,B,C,D ) \
    A = ROL32(A,8); B = ROR32(B,8); \
    C = ROL32(C,8); D = ROR32(D,8)

/* A macro to read the state from the plaintext */
#define GET_INPUT( src, A,B,C,D ) \
    A = GET32(src   ); B = GET32(src+ 4); \
    C = GET32(src+ 8); D = GET32(src+12)

/* Similar macro to put the ciphertext in the output buffer */
#define PUT_OUTPUT( A,B,C,D, dst ) \
    PUT32(A, dst   ); PUT32(B, dst+ 4); \
    PUT32(C, dst+ 8); PUT32(D, dst+12)


/*
 * Weakfish block encryption
 *
 * Arguments:
 * p            16 bytes of plaintext
 * c            16 bytes in which to store the ciphertext
 */
void Weakfish_encrypt(Byte p[16], Byte c[16])
{
    UInt32 A,B,C,D;         /* Working variables */

    /* Get the four plaintext words */
    GET_INPUT( p, A,B,C,D );

    /* Do encryption process */
    ENCRYPT( A,B,C,D );

    /* Store them with the final swap */
    PUT_OUTPUT( C,D,A,B, c );
}


/*
 * Weakfish block decryption.
 *
 * Arguments:
 * p            16 bytes of plaintext
 * c            16 bytes in which to store the ciphertext
 */
void Weakfish_decrypt(Byte c[16], Byte p[16])
{
    UInt32 A,B,C,D;         /* Working variables */

    /* Get the four plaintext words */
    GET_INPUT( c, A,B,C,D );

    /* Do decryption process */
    DECRYPT( A,B,C,D );

    /* Store them with the final swap */
    PUT_OUTPUT( C,D,A,B, p );
}
