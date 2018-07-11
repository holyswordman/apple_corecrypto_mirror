/*
 * Copyright (c) 2016,2018 Apple Inc. All rights reserved.
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

/* Autogenerated file - Use scheme ccdh_gen_gp to regenerate */
#include <corecrypto/ccdh_priv.h>
#include <corecrypto/ccdh_gp.h>

static ccdh_gp_decl_static(768) _ccdh_gp_apple768 =
{
    .hp = {
        .n = ccn_nof(768),
        .options = 0,
        .mod_prime = cczp_mod
    },
    .p = {
        /* prime */
        CCN64_C(ff,ff,ff,ff,ff,ff,ff,ff),CCN64_C(ec,14,ad,08,4d,0a,47,6d),
        CCN64_C(b7,99,6e,88,52,9b,1a,37),CCN64_C(cb,f6,08,fb,89,4c,72,97),
        CCN64_C(33,2d,de,fd,aa,e9,76,63),CCN64_C(bb,13,32,a7,10,44,f8,68),
        CCN64_C(55,2a,24,e1,69,ee,30,91),CCN64_C(66,c5,05,db,be,af,8d,dc),
        CCN64_C(94,61,9e,6e,28,fc,cd,a3),CCN64_C(d4,a0,df,17,fc,cd,b0,9a),
        CCN64_C(65,75,08,9b,a8,f8,37,3b),CCN64_C(ff,ff,ff,ff,ff,ff,ff,ff)
    },
    .recip = {
        /* recip */
        CCN64_C(a7,5d,fd,8e,10,5b,6a,bf),CCN64_C(da,31,ee,f9,23,dd,ff,35),
        CCN64_C(67,86,98,70,b1,e2,39,07),CCN64_C(14,f4,b7,a7,9d,63,7c,90),
        CCN64_C(7f,7f,33,d9,6b,ad,6d,c6),CCN64_C(c3,10,08,58,de,5a,20,bb),
        CCN64_C(d4,59,60,c4,4c,bd,69,d8),CCN64_C(b5,aa,7f,56,e9,17,68,3f),
        CCN64_C(3c,b3,55,75,ec,11,6e,01),CCN64_C(88,aa,9d,fc,63,28,48,9b),
        CCN64_C(9a,8a,f7,64,57,07,c8,c4),CCN64_C(00,00,00,00,00,00,00,00),
        CCN8_C(01)
    },
    .g = {
        /* g */
        CCN64_C(00,00,00,00,00,00,00,02),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN8_C(00)
    },
    .q = {
        /* q */
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN8_C(00)
    },
    .l = 160,
};

ccdh_const_gp_t ccdh_gp_apple768(void)
{
    return (ccdh_const_gp_t)(cczp_const_t)(const cc_unit *)&_ccdh_gp_apple768;
}
