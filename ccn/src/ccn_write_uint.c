/*
 * Copyright (c) 2010,2011,2015,2018 Apple Inc. All rights reserved.
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

#include <corecrypto/ccn.h>

/* TODO: This should really just named more generically like ccn_sizeof() */
size_t ccn_write_uint_size(cc_size count, const cc_unit *s)
{
#if 1
    /* Must faster/ smaller since this uses clz on arm. */
    return (ccn_bitlen(count, s) + 7) / 8;
#else
    count = ccn_n(count, s);
	if (count == 0) {
		return 0;
	}
    /* Count the number of leading 0 bytes in the m.s. unit. */
    cc_size num_zeros = 0;
    cc_unit msu = s[count - 1];
    for (cc_size byteIX = 0; byteIX < CCN_UNIT_SIZE; ++byteIX) {
        uint8_t byte = (uint8_t)msu;
        msu >>= 8;
        if (byte) {
            num_zeros = 0;
        } else {
            num_zeros++;
        }
    }
    return ccn_sizeof_n(count) - num_zeros;
#endif
}

/* Emit bytes starting at the far end of the outgoing byte
   stream, which is the l.s. byte of giant data. In order to prevent
   writing out leading zeros, we special case the m.s. digit. */
void ccn_write_uint(cc_size n, const cc_unit *s, size_t out_size, void *out)
{
    cc_unit v;
	uint8_t *ix = out;

    size_t s_size = ccn_write_uint_size(n, s);
    if (out_size > s_size)
        out_size = s_size;

    /* Start at the end. */
    ix += out_size;
    cc_size i = (s_size - out_size)/CCN_UNIT_SIZE;
    cc_size j = (s_size - out_size)%CCN_UNIT_SIZE;

    if(j) {
        /* First (partial) unit */
        v=s[i++];
        v >>= j*8;
        for (; j<CCN_UNIT_SIZE; ++j) {
            /* one loop per byte in v */
            *--ix = (uint8_t)v;
            v >>= 8;
            out_size--;
        }
    }

    for (;out_size >= CCN_UNIT_SIZE; out_size -= CCN_UNIT_SIZE) {
	    /* one loop per unit. */
        v = s[i++];

	    for (j = 0; j < CCN_UNIT_SIZE; ++j) {
	        /* one loop per byte in v */
            *--ix = (uint8_t)v;
			v >>= 8;
	    }
    }

    /* Handle the m.s. cc_unit, by writing out only as many bytes as are left.
       Since we already wrote out i units above the answer is (use i instead
       of n - 1 here to properly handle the case where n == 0. */
    if (out_size) {
        v = s[i];
        for (;out_size > 0; --out_size) {
            /* One loop per byte in the last unit v */
            *--ix = (uint8_t)v;
            v >>= 8;
        }
    }
}
