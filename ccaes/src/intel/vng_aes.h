/*
 * Copyright (c) 2012,2015,2016,2018 Apple Inc. All rights reserved.
 *
 * corecrypto Internal Use License Agreement
 *
 * IMPORTANT:  This Apple corecrypto software is supplied to you by Apple Inc. ("Apple")
 * in consideration of your agreement to the following terms, and your download or use
 * of this Apple software constitutes acceptance of these terms.  If you do not agree
 * with these terms, please do not download or use this Apple software.
 *
 * 1.    As used in this Agreement, the term "Apple Software" collectively means and
 * includes all of the Apple corecrypto materials provided by Apple here, including
 * but not limited to the Apple corecrypto software, frameworks, libraries, documentation
 * and other Apple-created materials. In consideration of your agreement to abide by the
 * following terms, conditioned upon your compliance with these terms and subject to
 * these terms, Apple grants you, for a period of ninety (90) days from the date you
 * download the Apple Software, a limited, non-exclusive, non-sublicensable license
 * under Apple’s copyrights in the Apple Software to make a reasonable number of copies
 * of, compile, and run the Apple Software internally within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software; provided
 * that you must retain this notice and the following text and disclaimers in all
 * copies of the Apple Software that you make. You may not, directly or indirectly,
 * redistribute the Apple Software or any portions thereof. The Apple Software is only
 * licensed and intended for use as expressly stated above and may not be used for other
 * purposes or in other contexts without Apple's prior written permission.  Except as
 * expressly stated in this notice, no other rights or licenses, express or implied, are
 * granted by Apple herein.
 *
 * 2.    The Apple Software is provided by Apple on an "AS IS" basis.  APPLE MAKES NO
 * WARRANTIES, EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION THE IMPLIED WARRANTIES
 * OF NON-INFRINGEMENT, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, REGARDING
 * THE APPLE SOFTWARE OR ITS USE AND OPERATION ALONE OR IN COMBINATION WITH YOUR PRODUCTS,
 * SYSTEMS, OR SERVICES. APPLE DOES NOT WARRANT THAT THE APPLE SOFTWARE WILL MEET YOUR
 * REQUIREMENTS, THAT THE OPERATION OF THE APPLE SOFTWARE WILL BE UNINTERRUPTED OR
 * ERROR-FREE, THAT DEFECTS IN THE APPLE SOFTWARE WILL BE CORRECTED, OR THAT THE APPLE
 * SOFTWARE WILL BE COMPATIBLE WITH FUTURE APPLE PRODUCTS, SOFTWARE OR SERVICES. NO ORAL
 * OR WRITTEN INFORMATION OR ADVICE GIVEN BY APPLE OR AN APPLE AUTHORIZED REPRESENTATIVE
 * WILL CREATE A WARRANTY.
 *
 * 3.    IN NO EVENT SHALL APPLE BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT, INCIDENTAL
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) ARISING
 * IN ANY WAY OUT OF THE USE, REPRODUCTION, COMPILATION OR OPERATION OF THE APPLE
 * SOFTWARE, HOWEVER CAUSED AND WHETHER UNDER THEORY OF CONTRACT, TORT (INCLUDING
 * NEGLIGENCE), STRICT LIABILITY OR OTHERWISE, EVEN IF APPLE HAS BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * 4.    This Agreement is effective until terminated. Your rights under this Agreement will
 * terminate automatically without notice from Apple if you fail to comply with any term(s)
 * of this Agreement.  Upon termination, you agree to cease all use of the Apple Software
 * and destroy all copies, full or partial, of the Apple Software. This Agreement will be
 * governed and construed in accordance with the laws of the State of California, without
 * regard to its choice of law rules.
 *
 * You may report security issues about Apple products to product-security@apple.com,
 * as described here:  https://www.apple.com/support/security/.  Non-security bugs and
 * enhancement requests can be made via https://bugreport.apple.com as described
 * here: https://developer.apple.com/bug-reporting/
 *
 * EA1350
 * 10/5/15
 */

/*
 * Parts of this code adapted from LibTomCrypt vng_aes.h
 *
 * LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtom.org
 */

#include <corecrypto/cc_config.h>

#if  CCAES_INTEL_ASM

#ifndef VNG_AES_H_
#define VNG_AES_H_

#include <stdint.h>


/* error codes [will be expanded in future releases] */
enum {
    CRYPT_OK=0,             /* Result OK */
    CRYPT_ERROR,            /* Generic Error */
    CRYPT_NOP,              /* Not a failure but no operation was performed */
    
    CRYPT_INVALID_KEYSIZE,  /* Invalid key size given */
    CRYPT_INVALID_ROUNDS,   /* Invalid number of rounds */
    CRYPT_FAIL_TESTVECTOR,  /* Algorithm failed test vectors */
    
    CRYPT_BUFFER_OVERFLOW,  /* Not enough space for output */
    CRYPT_INVALID_PACKET,   /* Invalid input packet given */
    
    CRYPT_INVALID_PRNGSIZE, /* Invalid number of bits for a PRNG */
    CRYPT_ERROR_READPRNG,   /* Could not read enough from PRNG */
    
    CRYPT_INVALID_CIPHER,   /* Invalid cipher specified */
    CRYPT_INVALID_HASH,     /* Invalid hash specified */
    CRYPT_INVALID_PRNG,     /* Invalid PRNG specified */
    
    CRYPT_MEM,              /* Out of memory */
    
    CRYPT_PK_TYPE_MISMATCH, /* Not equivalent types of PK keys */
    CRYPT_PK_NOT_PRIVATE,   /* Requires a private PK key */
    
    CRYPT_INVALID_ARG,      /* Generic invalid argument */
    CRYPT_FILE_NOTFOUND,    /* File Not Found */
    
    CRYPT_PK_INVALID_TYPE,  /* Invalid type of PK key */
    CRYPT_PK_INVALID_SYSTEM,/* Invalid PK system specified */
    CRYPT_PK_DUP,           /* Duplicate key already in key ring */
    CRYPT_PK_NOT_FOUND,     /* Key not found in keyring */
    CRYPT_PK_INVALID_SIZE,  /* Invalid size input for PK parameters */
    
    CRYPT_INVALID_PRIME_SIZE,/* Invalid size of prime requested */
    CRYPT_PK_INVALID_PADDING,/* Invalid padding on input */
    
    CRYPT_HASH_OVERFLOW,     /* Hash applied to too many bits */
    CRYPT_UNIMPLEMENTED,     /* called an unimplemented routine through a function table */
    CRYPT_PARAM,                /* Parameter Error */
    
    CRYPT_FALLBACK           /* Accelerator was called, but the input didn't meet minimum criteria - fallback to software */
};

#if defined(__cplusplus)
extern "C"
{
#endif
    
#define KS_LENGTH       60

typedef struct {   
	uint32_t ks[KS_LENGTH];
    	uint32_t rn;
} vng_aes_encrypt_ctx;

typedef struct {   
	uint32_t ks[KS_LENGTH];
	uint32_t rn;
} vng_aes_decrypt_ctx;

typedef struct {   
	vng_aes_encrypt_ctx encrypt;
	vng_aes_decrypt_ctx decrypt;
} vng_aes_ctx, vng_aes_keysched;
    
int vng_aes_xts_encrypt_opt(
                   const uint8_t *pt, size_t ptlen,
                   uint8_t *ct,
                   const uint8_t *tweak,
                   const void *xts);

int vng_aes_xts_encrypt_aesni(
                   const uint8_t *pt, size_t ptlen,
                   uint8_t *ct,
                   const uint8_t *tweak,
                   const void *xts);

int vng_aes_xts_decrypt_opt(
                   const uint8_t *ct, size_t ptlen,
                   uint8_t *pt,
                   const uint8_t *tweak,
                   const void *xts);
				
int vng_aes_xts_decrypt_aesni(
                   const uint8_t *ct, size_t ptlen,
                   uint8_t *pt,
                   const uint8_t *tweak,
                   const void *xts);


#if defined(__cplusplus)
}
#endif
#endif /* VNG_AES_H_ */
#endif  //CCAES_INTEL_ASM