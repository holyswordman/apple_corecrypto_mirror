/*
 * Copyright (c) 2016,2017,2018 Apple Inc. All rights reserved.
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

#include "cavs_common.h"

#include "cavs_vector_drbg.h"

#include <corecrypto/ccaes.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccsha1.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/cchmac.h>
#include <corecrypto/ccdrbg.h>
#include <corecrypto/ccdrbg_factory.h>

int cavs_vector_drbg(cavs_aes_is is, int pred_resist, size_t entropy_len,
        const uint8_t *entropy, size_t nonce_len, const uint8_t *nonce,
        size_t pers_len, const uint8_t *pers, size_t ent_reseed1_len,
        const uint8_t *ent_reseed1, size_t add1_len, const uint8_t *add1,
        size_t ent_reseed2_len, const uint8_t *ent_reseed2, size_t add2_len,
        const uint8_t *add2, uint8_t *result)
{
    struct ccdrbg_info info;
    struct ccdrbg_nistctr_custom custom;

    custom.ctr_info     = cavs_find_ccmode(is, CAVS_CIPHER_ENC_AES, CAVS_CIPHER_MODE_CTR, 1);
    custom.keylen       = 16;
    custom.strictFIPS   = 0;
    custom.use_df       = 1;

    if (!custom.ctr_info) {
        errorf("unsupported: %s", cavs_aes_is_to_string(is));
        return CAVS_STATUS_FAIL;
    }

    ccdrbg_factory_nistctr(&info, &custom);

    uint8_t state[info.size];
    struct ccdrbg_state* rng = (struct ccdrbg_state *)state;
    int rc;

    const size_t buf_len = 16;
    uint8_t buf[buf_len];

    if (!result) {
        /* Early exit; return the number of bytes expected in 'result'. */
        return buf_len;
    }

    rc = ccdrbg_init(&info, rng, entropy_len, entropy, nonce_len, nonce, pers_len, pers);
    if (rc) {
        errorf("failed ccdrg_init");
        return CAVS_STATUS_FAIL;
    }

    if (pred_resist) {
        rc = ccdrbg_reseed(&info, rng, ent_reseed1_len, ent_reseed1, add1_len, add1);
    } else {
        rc = ccdrbg_reseed(&info, rng, ent_reseed1_len, ent_reseed1, ent_reseed2_len, ent_reseed2);
    }
    if (rc) {
        errorf("failed ccdrbg_reseed");
        return CAVS_STATUS_FAIL;
    }

    if (pred_resist) {
        rc = ccdrbg_generate(&info, rng, buf_len, buf, 0, NULL);
    } else {
        rc = ccdrbg_generate(&info, rng, buf_len, buf, add1_len, add1);
    }
    if (rc) {
        errorf("failed ccdrbg_generate");
        return CAVS_STATUS_FAIL;
    }

    if (pred_resist) {
        rc = ccdrbg_reseed(&info, rng, ent_reseed2_len, ent_reseed2, add2_len, add2);
    }
    if (rc) {
        errorf("failed ccdrbg_reseed 2");
        return CAVS_STATUS_FAIL;
    }

    if (pred_resist) {
        rc = ccdrbg_generate(&info, rng, buf_len, buf, 0, NULL);
    } else {
        rc = ccdrbg_generate(&info, rng, buf_len, buf, add2_len, add2);
    }
    if (rc) {
        errorf("failed ccdrbg_generate 2");
        return CAVS_STATUS_FAIL;
    }

    memcpy(result, buf, buf_len);

    return CAVS_STATUS_OK;
}
