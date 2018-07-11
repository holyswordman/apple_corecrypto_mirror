/*
 * Copyright (c) 2010,2011,2015,2016,2018 Apple Inc. All rights reserved.
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

#include <corecrypto/cchmac.h>
#include <corecrypto/ccn.h>
#include <corecrypto/cc_priv.h>

/* The HMAC_<DIG> transform looks like:
   <DIG> (K XOR opad || <DIG> (K XOR ipad || text))
   Where K is a n byte key
   ipad is the byte 0x36 repeated 64 times.
   opad is the byte 0x5c repeated 64 times.
   text is the data being protected.
 */
void cchmac_init(const struct ccdigest_info *di, cchmac_ctx_t hc,
                 size_t key_len, const void *key_data) {
    const unsigned char *key = key_data;

    /* Set cchmac_data(di, hc) to key ^ opad. */
    size_t byte = 0;
	if (key_len <= di->block_size) {
        for (;byte < key_len; ++byte) {
            cchmac_data(di, hc)[byte] = key[byte] ^ 0x5c;
        }
    } else {
        /* Key is longer than di->block size, reset it to key=digest(key) */
        ccdigest_init(di, cchmac_digest_ctx(di, hc));
        ccdigest_update(di, cchmac_digest_ctx(di, hc), key_len, key);
        ccdigest_final(di, cchmac_digest_ctx(di, hc), cchmac_data(di, hc));
        key_len = di->output_size;
        for (;byte < key_len; ++byte) {
            cchmac_data(di, hc)[byte] ^= 0x5c;
        }
    }
    /* Fill remainder of cchmac_data(di, hc) with opad. */
	if (key_len < di->block_size) {
		CC_MEMSET(cchmac_data(di, hc) + key_len, 0x5c, di->block_size - key_len);
	}

    /* Set cchmac_ostate32(di, hc) to the state of the first round of the
       outer digest. */
    ccdigest_copy_state(di, cchmac_ostate32(di, hc), di->initial_state);
    di->compress(cchmac_ostate(di, hc), 1, cchmac_data(di, hc));

    /* Set cchmac_data(di, hc) to key ^ ipad. */
    for (byte = 0; byte < di->block_size; ++byte) {
        cchmac_data(di, hc)[byte] ^= (0x5c ^ 0x36);
    }
    ccdigest_copy_state(di, cchmac_istate32(di, hc), di->initial_state);
    di->compress(cchmac_istate(di, hc), 1, cchmac_data(di, hc));
    cchmac_num(di, hc) = 0;
    cchmac_nbits(di, hc) = di->block_size * 8;
}
