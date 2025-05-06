// Copyright (c) The mlkem-native project authors
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

#include <keccakf1600.h>

void harness(void)
{
  uint64_t *state;
  unsigned char *data;
  unsigned offset;
  unsigned length;
  mlk_keccakf1600_extract_bytes(state, data, offset, length);
}
