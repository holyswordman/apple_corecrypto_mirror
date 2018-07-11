# Copyright (c) 5832,6024,7258,8665,9255,9769 Apple Inc. All rights reserved.
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


#if CCAES_ARM_ASM
#if !defined(__arm64__)

    /*
            armv7 implementation of ccm-encrypt functions

            void ccm_encrypt(void *in, void *out, void *tag, int nblocks, void *key, void *ctr, int ctr_len);

            ctr_len : 2-7, meaning the number of bytes that will increment inside ctr
    */


#define pin     r4
#define pout    r5
#define ptag    r6
#define nblocks r8
#define pctr    r10


/*
    ccaes_arm_encrypt(const unsigned char *in, unsigned char *out, const ccaes_arm_encrypt_ctx cx[1]);
*/
    .extern _ccaes_arm_encrypt

    .syntax unified
    .align  2
    .code   16
    .thumb_func _ccm_encrypt 

    .globl _ccm_encrypt
_ccm_encrypt:

/* set up often used constants in registers */
    push    {r4-r7,lr}
    add     r7, sp, #12     // setup frame pointer
    push    {r8,r10,r11}
    sub     sp, sp, #32

    mov     pin, r0
    mov     pout, r1
    mov     ptag, r2
    mov     nblocks, r3
    ldr     pctr, [r7, #12]
    ldr     r12, [r7, #16]      // ctr_len 2:7

    /*
        precompute mask for ctr_len 
            2 : 0000 0000 0000 FFFF
            7 : 00FF FFFF FFFF FFFF
    */
    cmp     r12, 4
    bgt     1f
    rsb     r12, #4
    mov     r0, #-1
    mov     r1, #0
    lsl     r12, #3
    lsr     r0, r12
    b       2f
1:
    mov     r1, #-1
    mov     r0, #-1
    rsb     r12, #8
    lsl     r12, #3
    lsr     r1, r12
2:
    strd    r0, r1, [sp, #24]

    /*
        read ctr higher half, byte swap, save in stack
    */
    ldrd    r2, r3, [pctr, #8]
    rev     r2, r2
    rev     r3, r3
    strd    r2, r3, [sp, #16]

0:

    /* ++ctr */
    ldrd    r2, r3, [sp, #16]       // ctr high half
    adds    r0, r3, #1              //  
    ldr     r12, [sp, #24]
    adc     r1, r2, #0              // r1:r0 = ctr+1 in 8bytes 
    and     r0, r0, r12
    bic     r3, r3, r12
    ldr     r12, [sp, #28]
    and     r1, r1, r12
    bic     r2, r2, r12
    orr     r3, r3, r0
    orr     r2, r2, r1
    strd    r2, r3, [sp, #16]       // ctr high half
    rev     r2, r2
    rev     r3, r3
    strd    r2, r3, [pctr, #8]

    /* tmp = aes_encrypt(++ctr) */
    mov     r0, pctr
    mov     r1, sp
    ldr     r2, [r7, #8]            // key
    bl      _ccaes_arm_encrypt

    /* ct = pt ^ tmp */
    ldmia   sp, {r0-r3} // tmp
    ldr     r9, [pin] , #4
    ldr     r11, [pin], #4
    ldr     r12, [pin], #4 
    ldr     lr, [pin], #4 
    eor     r0, r0, r9
    eor     r1, r1, r11
    eor     r2, r2, r12
    eor     r3, r3, lr
    str     r0, [pout], #4
    str     r1, [pout], #4
    str     r2, [pout], #4
    str     r3, [pout], #4

    /* tag ^= pt */
    ldr     r0, [ptag]
    ldr     r1, [ptag, #4]
    ldr     r2, [ptag, #8]
    ldr     r3, [ptag, #12]
    eor     r0, r0, r9
    eor     r1, r1, r11
    eor     r2, r2, r12
    eor     r3, r3, lr
    stmia   sp, {r0-r3}

    /* tag = aes_encrypt(tag) */
    mov     r0, sp
    mov     r1, ptag
    ldr     r2, [r7, #8]            // key
    bl      _ccaes_arm_encrypt

    subs    nblocks, #1
    bgt     0b
    
    add     sp, sp, #32

    pop     {r8,r10,r11}
    pop     {r4-r7,pc}

#endif  // __armv7__ w __ARM_NEON__
#endif  // CCAES_ARM_ASM

