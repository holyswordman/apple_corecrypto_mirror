# Copyright (c) 2010,2012,2015,2016,2018 Apple Inc. All rights reserved.
#
# corecrypto Internal Use License Agreement
#
# IMPORTANT:  This Apple corecrypto software is supplied to you by Apple Inc. ("Apple")
# in consideration of your agreement to the following terms, and your download or use
# of this Apple software constitutes acceptance of these terms.  If you do not agree
# with these terms, please do not download or use this Apple software.
#
# 1.    As used in this Agreement, the term "Apple Software" collectively means and
# includes all of the Apple corecrypto materials provided by Apple here, including
# but not limited to the Apple corecrypto software, frameworks, libraries, documentation
# and other Apple-created materials. In consideration of your agreement to abide by the
# following terms, conditioned upon your compliance with these terms and subject to
# these terms, Apple grants you, for a period of ninety (90) days from the date you
# download the Apple Software, a limited, non-exclusive, non-sublicensable license
# under Apple’s copyrights in the Apple Software to make a reasonable number of copies
# of, compile, and run the Apple Software internally within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software; provided
# that you must retain this notice and the following text and disclaimers in all
# copies of the Apple Software that you make. You may not, directly or indirectly,
# redistribute the Apple Software or any portions thereof. The Apple Software is only
# licensed and intended for use as expressly stated above and may not be used for other
# purposes or in other contexts without Apple's prior written permission.  Except as
# expressly stated in this notice, no other rights or licenses, express or implied, are
# granted by Apple herein.
#
# 2.    The Apple Software is provided by Apple on an "AS IS" basis.  APPLE MAKES NO
# WARRANTIES, EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION THE IMPLIED WARRANTIES
# OF NON-INFRINGEMENT, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, REGARDING
# THE APPLE SOFTWARE OR ITS USE AND OPERATION ALONE OR IN COMBINATION WITH YOUR PRODUCTS,
# SYSTEMS, OR SERVICES. APPLE DOES NOT WARRANT THAT THE APPLE SOFTWARE WILL MEET YOUR
# REQUIREMENTS, THAT THE OPERATION OF THE APPLE SOFTWARE WILL BE UNINTERRUPTED OR
# ERROR-FREE, THAT DEFECTS IN THE APPLE SOFTWARE WILL BE CORRECTED, OR THAT THE APPLE
# SOFTWARE WILL BE COMPATIBLE WITH FUTURE APPLE PRODUCTS, SOFTWARE OR SERVICES. NO ORAL
# OR WRITTEN INFORMATION OR ADVICE GIVEN BY APPLE OR AN APPLE AUTHORIZED REPRESENTATIVE
# WILL CREATE A WARRANTY.
#
# 3.    IN NO EVENT SHALL APPLE BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT, INCIDENTAL
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
# GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) ARISING
# IN ANY WAY OUT OF THE USE, REPRODUCTION, COMPILATION OR OPERATION OF THE APPLE
# SOFTWARE, HOWEVER CAUSED AND WHETHER UNDER THEORY OF CONTRACT, TORT (INCLUDING
# NEGLIGENCE), STRICT LIABILITY OR OTHERWISE, EVEN IF APPLE HAS BEEN ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# 4.    This Agreement is effective until terminated. Your rights under this Agreement will
# terminate automatically without notice from Apple if you fail to comply with any term(s)
# of this Agreement.  Upon termination, you agree to cease all use of the Apple Software
# and destroy all copies, full or partial, of the Apple Software. This Agreement will be
# governed and construed in accordance with the laws of the State of California, without
# regard to its choice of law rules.
#
# You may report security issues about Apple products to product-security@apple.com,
# as described here:  https://www.apple.com/support/security/.  Non-security bugs and
# enhancement requests can be made via https://bugreport.apple.com as described
# here: https://developer.apple.com/bug-reporting/
#
# EA1350
# 10/5/15

#include <corecrypto/cc_config.h>


#if (defined(_ARM_ARCH_7) || defined(__arm64__)) && CCN_SUB_ASM

.text
.align 2
#if defined(_ARM_ARCH_7)
    .syntax unified
    .code   16
    .thumb_func _ccn_sub
#endif


	.globl _ccn_sub

/* r0 = count, r1 = r, r2 = s, r3 = t */
_ccn_sub: /* unsigned int ccn_sub(unsigned int count, void *r, const void *s, const void *t); */

#if defined(__arm64__)

	subs		x4, x4, x4		// clear carry signal

	// if count == 0, return with carry = 0
	cbnz		x0, 1f
	ret			lr
1:

	#define	count	w0
	#define	r		x1
	#define	x		x2
	#define	y		x3

	and			w12, count, #1
	cbz			w12, L_skip1
	ldr		x4,[x],#8
	ldr		x8,[y],#8
	subs	x8, x4, x8
	str		x8, [r], #8	
L_skip1:
	and			w12, count, #2
	cbz			w12, L_skip2
	ldp		x4,x5,[x],#16
	ldp		x8,x9,[y],#16
	sbcs	x8, x4, x8
	sbcs	x9, x5, x9
	stp		x8,x9,[r],#16
L_skip2:
    and    count, count, #0xfffffffc
	cbz		count, L_done

	sub		count, count, #4
	ldp		x4,x5,[x],#16
	ldp		x8,x9,[y],#16
	ldp		x6,x7,[x],#16
	ldp		x10,x11,[y],#16

	cbz		count, L_loop4_finishup

L_loop4:

	sbcs	x8, x4, x8
	sbcs	x9, x5, x9
	ldp		x4,x5,[x],#16
	sbcs	x10, x6, x10
	stp		x8,x9,[r],#16
	sbcs	x11, x7, x11
	ldp		x8,x9,[y],#16
	stp		x10,x11,[r],#16
	sub		count, count, #4
	ldp		x6,x7,[x],#16
	ldp		x10,x11,[y],#16

	cbnz	count, L_loop4

L_loop4_finishup:

	sbcs	x8, x4, x8
	sbcs	x9, x5, x9
	sbcs	x10, x6, x10
	sbcs	x11, x7, x11
	stp		x8,x9,[r],#16
	stp		x10,x11,[r],#16

L_done:
	sbc		w0, w0, w0
	and		w0, w0, #1
	ret		lr

#elif defined(_ARM_ARCH_7)		// arm architecture

    stmfd   sp!, { r4-r10, lr }
	subs	r12, r12, r12
	tst     r0, #1
    beq     Lskipcount1
    ldr     r12, [r2], #4
    ldr     lr, [r3], #4
    subs    r12, r12, lr
    str     r12, [r1], #4
Lskipcount1:
    tst     r0, #2
    beq     Lskipcount2
    ldmia   r2!, { r8, r9 }
    ldmia   r3!, { r12, lr }
    sbcs    r8, r8, r12
    sbcs    r9, r9, lr
    stmia   r1!, { r8, r9 }
Lskipcount2:
    bics    r0, r0, #3
    beq     Ldone
Ldo_count4loop:
    ldmia	r2!, { r4, r5, r6, r10 }
    ldmia	r3!, { r8, r9, r12, lr }
    sbcs	r4, r4, r8
    /* Cache prefetch write line */
#if defined(__arm__)    // _ARM_ARCH_6 
    pld     [r1, #12]
#elif defined(_ARM_ARCH_7)
    pldw    [r1, #12]
#else
    ldr     r8, [r1, #12]
#endif
    sbcs    r5, r5, r9
    sbcs    r6, r6, r12
    sbcs    r10, r10, lr
    stmia   r1!, { r4, r5, r6, r10 }
    sub     r0, r0, #4
    teq     r0, #0
    bne     Ldo_count4loop
Ldone:
    sbc     r0, r0, r0
    and     r0, r0, #1                  /* Return carry */
    ldmfd	sp!, { r4-r10, pc }

#endif	/* arm64 or arm */

#endif /* (defined(_ARM_ARCH_7) || defined(__arm64__)) && CCN_SUB_ASM */


