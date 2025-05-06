/*
 * Copyright (c) The mlkem-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

#ifdef MLK_FIPS202_PROFILE_H
#error Only one MLKEM_FIPS202 assembly profile can be defined -- did you include multiple profiles?
#else
#define MLK_FIPS202_PROFILE_H

#define MLK_USE_FIPS202_X4_NATIVE
#include "../../mlkem/fips202/native/api.h"

#endif /* !MLK_FIPS202_PROFILE_H */
