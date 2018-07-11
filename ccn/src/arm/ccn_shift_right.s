# Copyright (c) 2016,2018 Apple Inc. All rights reserved.
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


#if (defined(_ARM_ARCH_7) || defined(__arm64__)) && CCN_SHIFT_RIGHT_ASM

	.text
	.align 2

#if defined(__arm__)
    .syntax unified
    .code   16
    .thumb_func _ccn_shift_right 
#endif

	.globl _ccn_shift_right

_ccn_shift_right: /* cc_unit ccn_shift_right(cc_size count, cc_unit *r, const cc_unit *s, size_t k) */

#if defined(__arm64__) 

	#define	count	x0
	#define	dst		x1
	#define	src		x2
	#define	k		x3
	#define	rk		x10

    cbnz        count, 1f
    ret         lr          // if count == 0, return x0 = 0
1:
    cbnz        k, 1f
    // if k==0, call ccn_set (same 1st 3 arguments), and return 0
    sub         sp, sp, #16
    str         lr, [sp]
    bl          _ccn_set
    ldr         lr, [sp]
    add         sp, sp, #16
    mov         x0, #0
    ret         lr
1:

#if CC_KERNEL
    // save v0-v5
    sub     x4, sp, #6*16
    sub     sp, sp, #6*16
    st1.4s  {v0, v1, v2, v3}, [x4], #64
    st1.4s  {v4, v5}, [x4], #32
#endif

    mov         rk, #64
    ldr         x5, [src]
    sub         rk, rk, k           // left shift amount = 64 - k
    lsl         x6, x5, rk          // carry to be returned 

    // vector implementation
    neg         x7, k               // negative right shift for ushl instruction
    dup.2d      v5, rk              // for left shift 
    dup.2d      v4, x7              // for right shift using ushl 

    subs    count, count, #4        // pre-subtract count by 4
    b.lt        9f                  // less than 4 elements,
    b.eq        8f                  // with exact 4 elemnts to process, no more element to read

    // 4 elements to process, with at least 1 extra to read
0: 
    ld1.2d {v0, v1}, [src], #2*16  // read 4 data, v0 = 1:0, v1 = 3:2
    ext.16b v2, v0, v1, #8          // form v2 = 2:1,
    ldr     x5, [src]               // 4
    ext.16b v3, v1, v1, #8          // form v2 = 2:3,
    mov     v3.d[1], x5             // v3 = 4:3
    ushl.2d v0, v0, v4
    ushl.2d v1, v1, v4
    ushl.2d v2, v2, v5
    ushl.2d v3, v3, v5
    eor.16b v0, v0, v2
    eor.16b v1, v1, v3
    st1.2d {v0, v1}, [dst], #2*16
    subs    count, count, #4        // subtract count by 4
    b.gt        0b                  // more than 4 elements
    b.lt        9f                  // less than 4 elements left
 
8:  // exactly 4 more elements to process
    ld1.2d {v0, v1}, [src], #2*16   // read 4 data, v0 = 1:0, v1 = 3:2
    ext.16b v2, v0, v1, #8          // form v2 = 2:1,
    mov     x5, #0                  // 4
    ext.16b v3, v1, v1, #8          // form v2 = 2:3,
    mov     v3.d[1], x5             // v3 = 4:3
    ushl.2d v0, v0, v4
    ushl.2d v1, v1, v4
    ushl.2d v2, v2, v5
    ushl.2d v3, v3, v5
    eor.16b v0, v0, v2
    eor.16b v1, v1, v3
    st1.2d {v0, v1}, [dst], #2*16
    b       L_done

9:  add     count, count, #4        // recover count and src for remaining code
    add     src, src, #8

    /* process 2 units per iteration */
    subs        count, count, #2
    b.lt        9f                      // 1 lelment in x5
    b.eq        8f                      // 2 elments, with 1st in x5
0:
    ldp         x7, x8, [src], #16      // read 2 more elements
    lsr         x4, x5, k
    lsr         x5, x7, k
    lsl         x7, x7, rk
    lsl         x9, x8, rk
    orr         x4, x4, x7
    orr         x5, x5, x9
    stp         x4, x5, [dst], #16
    mov         x5, x8
    subs        count, count, #2
    b.gt        0b
    b.lt        9f
8:  ldr         x4, [src]               // final src elemnt
    lsr         x7, x5, k
    lsr         x8, x4, k
    lsl         x4, x4, rk 
    orr         x7, x7, x4
    stp         x7, x8, [dst], #16
    b           L_done

9:  lsr         x5, x5, k
    str         x5, [dst]

L_done:
#if CC_KERNEL
    // restore v0-v5
    ld1.4s  {v0, v1, v2, v3}, [sp], #64
    ld1.4s  {v4, v5}, [sp], #32
#endif

    mov         x0, x6
    ret         lr

#elif defined(__arm__)

    #define count   r0
    #define dst     r1
    #define src     r2
    #define k       r3

    cbnz        count, 1f
    bx          lr          // if count == 0, return x0 = 0
1:
    cbnz        k, 1f
    // if k==0, call ccn_set (same 1st 3 arguments), and return 0
    sub         sp, sp, #16
    str         lr, [sp]
    bl          _ccn_set
    ldr         lr, [sp]
    add         sp, sp, #16
    mov         r0, #0
    bx          lr
1:
    
    rsb     r12, r3, #32
    stmfd   sp!, { r4-r6, r8-r11, lr }
    ldr     r11, [src]
    lsl     r11, r12                        // carry to be returned

    subs    count, count, #4
    blt     L_lessthan4
0:
    ldmia   src!, {r4-r6, r8}               // read 4 elements
    it      gt
    ldrgt   r9, [src]
    lsr     r4, k
    lsl     r10, r5, r12
    lsl     lr, r6, r12
    lsr     r5, k
    orr     r4, r10
    orr     r5, lr
    lsl     r10, r8, r12
    it      gt
    lslgt   lr, r9, r12
    lsr     r6, k
    lsr     r8, k
    orr     r6, r10
    it      gt
    orrgt   r8, lr
#if defined(__arm__)                    // _ARM_ARCH_6
    pld     [dst, #12]                   /* Cache prefetch write line */
#elif defined(_ARM_ARCH_7)
    pldw    [dst, #12]                   /* Cache prefetch write line */
#else
    ldr     r9, [dst, #12]               /* Cache prefetch write line */
#endif
    stmia   dst!, { r4-r6, r8 }

    subs    count, count, #4
    bge     0b

L_lessthan4:

    adds    count, count, #2
    blt     L_lessthan2
    ldmia   src!, {r4-r5}               // read 2 elements
    it      gt
    ldrgt   r9, [src]
    lsr     r4, k
    lsl     r10, r5, r12
    lsr     r5, k
    it      gt
    lslgt   lr, r9, r12
    orr     r4, r10
    it      gt
    orrgt   r5, lr
    stmia   dst!, { r4-r5 }

L_lessthan2:

    tst     r0, #1
    beq     1f
    ldr     r4, [src]
    lsr     r4, k
    str     r4, [dst]
1:

L_done:
    mov     r0, r11
    ldmfd	sp!, { r4-r6, r8-r11, pc }

#endif	/* __arm64__ */

#endif /* CCN_SHIFT_RIGHT_ASM */

