/*
 * Copyright (c) The mlkem-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/* References
 * ==========
 *
 * - [REF_AVX2]
 *   CRYSTALS-Kyber optimized AVX2 implementation
 *   Bos, Ducas, Kiltz, Lepoint, Lyubashevsky, Schanck, Schwabe, Seiler, Stehlé
 *   https://github.com/pq-crystals/kyber/tree/main/avx2
 */

/*
 * This file is derived from the public domain
 * AVX2 Kyber implementation [@REF_AVX2].
 */

#include "../../../common.h"

#if defined(MLK_ARITH_BACKEND_X86_64_DEFAULT) && \
    !defined(MLK_CONFIG_MULTILEVEL_NO_SHARED)
/* simpasm: header-end */

#include "consts.h"
#include "fq.inc"
#include "shuffle.inc"

.text
.global MLK_ASM_NAMESPACE(nttpack_avx2)
.balign 4
MLK_ASM_FN_SYMBOL(nttpack_avx2)
#load
vmovdqa		(%rdi),%ymm4
vmovdqa		32(%rdi),%ymm5
vmovdqa		64(%rdi),%ymm6
vmovdqa		96(%rdi),%ymm7
vmovdqa		128(%rdi),%ymm8
vmovdqa		160(%rdi),%ymm9
vmovdqa		192(%rdi),%ymm10
vmovdqa		224(%rdi),%ymm11

shuffle1	4,5,3,5
shuffle1	6,7,4,7
shuffle1	8,9,6,9
shuffle1	10,11,8,11

shuffle2	3,4,10,4
shuffle2	6,8,3,8
shuffle2	5,7,6,7
shuffle2	9,11,5,11

shuffle4	10,3,9,3
shuffle4	6,5,10,5
shuffle4	4,8,6,8
shuffle4	7,11,4,11

shuffle8	9,10,7,10
shuffle8	6,4,9,4
shuffle8	3,5,6,5
shuffle8	8,11,3,11

#store
vmovdqa		%ymm7,(%rdi)
vmovdqa		%ymm9,32(%rdi)
vmovdqa		%ymm6,64(%rdi)
vmovdqa		%ymm3,96(%rdi)
vmovdqa		%ymm10,128(%rdi)
vmovdqa		%ymm4,160(%rdi)
vmovdqa		%ymm5,192(%rdi)
vmovdqa		%ymm11,224(%rdi)

ret

/* simpasm: footer-start */
#endif /* MLK_ARITH_BACKEND_X86_64_DEFAULT && !MLK_CONFIG_MULTILEVEL_NO_SHARED \
        */
