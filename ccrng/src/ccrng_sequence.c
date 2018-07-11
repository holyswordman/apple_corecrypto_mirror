/*
 * Copyright (c) 2013,2014,2015,2016,2017,2018 Apple Inc. All rights reserved.
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

/* This is a RNG that is deterministic -  useful for testing */

/* 
    RNG that reads byte from an array set a init time.
    It starts from the beginning of the buffer on every generate.
    When exceeding the length, it rolls over silently.
    If the lenght of the sequence is 0, it returns an error
 */

#include <corecrypto/ccrng_sequence.h>

static int sequence_repeat_generate(struct ccrng_state *rng, size_t entropy_size, void *entropy)
{
    struct ccrng_sequence_state *thisrng = (struct ccrng_sequence_state *)rng;
    uint8_t *e_bytes = (uint8_t *) entropy;
    if (thisrng->len==0) return CCERR_CRYPTO_CONFIG;
    for(size_t i=0; i<entropy_size; i++) {
        e_bytes[i] = thisrng->state[i%thisrng->len];
    }
    return 0;
}

int ccrng_sequence_init(struct ccrng_sequence_state *rng, size_t len, const uint8_t *sequence)
{
    rng->generate=sequence_repeat_generate;
    rng->state=sequence;
    rng->len=len;
    return 0;
}

static int non_repeat_sequence_generate(struct ccrng_state *rng, size_t entropy_size, void *entropy)
{
    struct ccrng_sequence_state *thisrng = (struct ccrng_sequence_state *)rng;
    uint8_t *e_bytes = (uint8_t *) entropy;
    if (thisrng->len<entropy_size) return CCERR_OUT_OF_ENTROPY;
    for(size_t i=0; i<entropy_size; i++) {
        e_bytes[i] = thisrng->state[i];
    }
    thisrng->state+=entropy_size;
    thisrng->len-=entropy_size;
    return 0;
}

int ccrng_sequence_non_repeat_init(struct ccrng_sequence_state *rng, size_t len, const uint8_t *sequence)
{
    rng->generate=non_repeat_sequence_generate;
    rng->state=sequence;
    rng->len=len;
    return 0;
}

