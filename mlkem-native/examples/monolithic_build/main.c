/*
 * Copyright (c) The mlkem-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Import public mlkem-native API
 *
 * This requires specifying the parameter set and namespace prefix
 * used for the build.
 *
 * The parameter set is configured on the command line
 */
#define MLK_CONFIG_API_NAMESPACE_PREFIX mlkem
#include <mlkem_native.h>
#include "test_only_rng/notrandombytes.h"

#define CHECK(x)                                              \
  do                                                          \
  {                                                           \
    int rc;                                                   \
    rc = (x);                                                 \
    if (!rc)                                                  \
    {                                                         \
      fprintf(stderr, "ERROR (%s,%d)\n", __FILE__, __LINE__); \
      return 1;                                               \
    }                                                         \
  } while (0)

static int test_keys_mlkem(void)
{
  /* The PCT modifies the PRNG state, so the KAT tests don't work.
   * We run KAT tests only for disabled PCT. */
#if !defined(MLK_CONFIG_KEYGEN_PCT)
#if MLK_CONFIG_API_PARAMETER_SET == 512
  const uint8_t expected_key[] = {
      0x77, 0x6c, 0x74, 0xdf, 0x30, 0x1f, 0x8d, 0x82, 0x52, 0x5e, 0x8e,
      0xbb, 0xb4, 0x00, 0x95, 0xcd, 0x2e, 0x92, 0xdf, 0x6d, 0xc9, 0x33,
      0xe7, 0x86, 0x62, 0x59, 0xf5, 0x31, 0xc7, 0x35, 0x0a, 0xd5};
#elif MLK_CONFIG_API_PARAMETER_SET == 768
  const uint8_t expected_key[] = {
      0xe9, 0x13, 0x77, 0x84, 0x0e, 0x6b, 0x66, 0x94, 0xea, 0xa9, 0xf0,
      0x1c, 0x97, 0xff, 0x68, 0x87, 0x4e, 0x8b, 0x0c, 0x52, 0x0b, 0x00,
      0xc2, 0xcd, 0xe3, 0x7c, 0x4f, 0xc2, 0x39, 0x62, 0x6e, 0x70};
#elif MLK_CONFIG_API_PARAMETER_SET == 1024
  const uint8_t expected_key[] = {
      0x5d, 0x9e, 0x23, 0x5f, 0xcc, 0xb2, 0xb3, 0x49, 0x9a, 0x5f, 0x49,
      0x0a, 0x56, 0xe3, 0xf0, 0xd3, 0xfd, 0x9b, 0x58, 0xbd, 0xa2, 0x8b,
      0x69, 0x0f, 0x91, 0xb5, 0x7b, 0x88, 0xa5, 0xa8, 0x0b, 0x90};
#endif /* MLK_CONFIG_API_PARAMETER_SET == 1024 */
#endif /* !MLK_CONFIG_KEYGEN_PCT */

  uint8_t pk[MLKEM_PUBLICKEYBYTES(MLK_CONFIG_API_PARAMETER_SET)];
  uint8_t sk[MLKEM_SECRETKEYBYTES(MLK_CONFIG_API_PARAMETER_SET)];
  uint8_t ct[MLKEM_CIPHERTEXTBYTES(MLK_CONFIG_API_PARAMETER_SET)];
  uint8_t key_a[MLKEM_BYTES];
  uint8_t key_b[MLKEM_BYTES];

  /* WARNING: Test-only
   * Normally, you would want to seed a PRNG with trustworthy entropy here. */
  randombytes_reset();

  /* Alice generates a public key */
  CHECK(mlkem_keypair(pk, sk) == 0);

  /* Bob derives a secret key and creates a response */
  CHECK(mlkem_enc(ct, key_b, pk) == 0);

  /* Alice uses Bobs response to get her shared key */
  CHECK(mlkem_dec(key_a, ct, sk) == 0);

  CHECK(memcmp(key_a, key_b, MLKEM_BYTES) == 0);

  printf("Shared secret: ");
  {
    size_t i;
    for (i = 0; i < sizeof(key_a); i++)
    {
      printf("%02x", key_a[i]);
    }
  }
  printf("\n");

#if !defined(MLK_CONFIG_KEYGEN_PCT)
  /* Check against hardcoded result to make sure that
   * we integrated custom FIPS202 correctly */
  CHECK(memcmp(key_a, expected_key, sizeof(key_a)) == 0);
#else
  printf(
      "[WARNING] Skipping KAT test since PCT is enabled and modifies PRNG\n");
#endif

  printf("[MLKEM-%d] OK\n", MLK_CONFIG_API_PARAMETER_SET);
  return 0;
}

int main(void)
{
  if (test_keys_mlkem() != 0)
  {
    return 1;
  }

  return 0;
}
