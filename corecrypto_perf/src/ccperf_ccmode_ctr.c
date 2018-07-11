/*
 * Copyright (c) 2011,2013,2014,2015,2016,2017,2018 Apple Inc. All rights reserved.
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
#include <corecrypto/ccperf.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/ccmode_factory.h>
#include "ccaes_vng_ctr.h"

/* mode created with the CTR factory */
static struct ccmode_ctr ccaes_generic_ltc_ctr_crypt_mode;
static struct ccmode_ctr ccaes_default_aes_ctr_crypt_mode;

#if CCMODE_CTR_VNG_SPEEDUP
static struct ccmode_ctr ccaes_vng_aes_ctr_crypt_mode;
#endif

#define CCMODE_CTR_TEST(_mode, _keylen) { .name=#_mode"_"#_keylen, .ctr=&_mode, .keylen=_keylen }

static struct ccctr_perf_test {
    const char *name;
    const struct ccmode_ctr *ctr;
    size_t keylen;
} ccctr_perf_tests[] = {
    CCMODE_CTR_TEST(ccaes_default_aes_ctr_crypt_mode, 16),
    CCMODE_CTR_TEST(ccaes_default_aes_ctr_crypt_mode, 24),
    CCMODE_CTR_TEST(ccaes_default_aes_ctr_crypt_mode, 32),

    CCMODE_CTR_TEST(ccaes_generic_ltc_ctr_crypt_mode, 16),
    CCMODE_CTR_TEST(ccaes_generic_ltc_ctr_crypt_mode, 24),
    CCMODE_CTR_TEST(ccaes_generic_ltc_ctr_crypt_mode, 32),

#if CCMODE_CTR_VNG_SPEEDUP
    CCMODE_CTR_TEST(ccaes_vng_aes_ctr_crypt_mode, 16),
    CCMODE_CTR_TEST(ccaes_vng_aes_ctr_crypt_mode, 24),
    CCMODE_CTR_TEST(ccaes_vng_aes_ctr_crypt_mode, 32),
#endif

#if CCAES_MUX
    CCMODE_CTR_TEST(ccaes_ios_hardware_ctr_crypt_mode, 16),
    CCMODE_CTR_TEST(ccaes_ios_hardware_ctr_crypt_mode, 24),
    CCMODE_CTR_TEST(ccaes_ios_hardware_ctr_crypt_mode, 32),
#endif

};

static double perf_ccctr_init(size_t loops, size_t size  CC_UNUSED, const void *arg)
{
    const struct ccctr_perf_test *test=arg;
    const struct ccmode_ctr *ctr=test->ctr;
    size_t keylen=test->keylen;

    unsigned char keyd[keylen];
    unsigned char ivd[ctr->block_size];

    cc_zero(keylen,keyd);
    ccctr_ctx_decl(ctr->size, key);

    perf_start();
    while(loops--) {
        int ret;
        ret=ccctr_init(ctr, key, keylen, keyd, ivd);
        if (ret) return 0;
    }

    return perf_seconds();
}

static double perf_ccctr_update(size_t loops, size_t size, const void *arg)
{
    const struct ccctr_perf_test *test=arg;
    const struct ccmode_ctr *ctr=test->ctr;
    size_t keylen=test->keylen;
    size_t nblocks=size/ctr->block_size;

    unsigned char keyd[keylen];
    unsigned char ivd[ctr->block_size];
    unsigned char temp[nblocks*ctr->block_size];

    cc_zero(keylen,keyd);
    cc_zero(sizeof(ivd),ivd);
    ccctr_ctx_decl(ctr->size, key);

    int ret;
    ret=ccctr_init(ctr, key, keylen, keyd, ivd);
    if (ret) return 0;

    perf_start();
    while(loops--) {
        ret=ccctr_update(ctr,key, size, temp, temp);
        if (ret) abort();
    }

    return perf_seconds();
}

static double perf_ccctr_one_shot(size_t loops, size_t size, const void *arg)
{
    const struct ccctr_perf_test *test=arg;
    const struct ccmode_ctr *ctr=test->ctr;
    size_t keylen=test->keylen;
    size_t nblocks=size/ctr->block_size;

    unsigned char keyd[keylen];
    unsigned char ivd[ctr->block_size];
    unsigned char temp[nblocks*ctr->block_size];

    cc_zero(keylen,keyd);
    cc_zero(sizeof(ivd),ivd);

    perf_start();
    while(loops--) {
        int ret=ccctr_one_shot(ctr,keylen, keyd, ivd, size, temp, temp);
        if (ret) return 0;
    }

    return perf_seconds();
}


static void ccperf_family_ccctr_once(int argc CC_UNUSED, char *argv[] CC_UNUSED)
{
    ccmode_factory_ctr_crypt(&ccaes_generic_ltc_ctr_crypt_mode, &ccaes_ltc_ecb_encrypt_mode);
    ccaes_default_aes_ctr_crypt_mode=*ccaes_ctr_crypt_mode();
#if CCMODE_CTR_VNG_SPEEDUP
    ccaes_vng_ctr_crypt_mode_setup(&ccaes_vng_aes_ctr_crypt_mode);
#endif
}

F_DEFINE(ccctr, init,     ccperf_size_iterations, 1, 1)
F_DEFINE(ccctr, update,   ccperf_size_bytes,      5, 1024)
F_DEFINE(ccctr, one_shot, ccperf_size_bytes,      5, 1024)
