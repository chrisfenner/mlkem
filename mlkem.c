/*
 * Copyright (c) The mlkem-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * cgo doesn't do anything clever like traverse the directory for C files.
 * This file is essentially a copy of the example in mlkem-native/examples/monolithic_build_multileve.
*/  

/* Only include API to check consistency with mlkem/mlkem_native.h
 * imported into the individual builds below via MLK_CHECK_APIS. */
 #include "internal/mlkem_native_all.h"

 /* All randomness will be provided by the caller from the Go interface. */
 #include "mlkem-native/test/notrandombytes/notrandombytes.c"

 /* Include mlkem_native.h into each level-build to ensure consistency
  * with kem.h and mlkem_native_all.h above. */
 #define MLK_CHECK_APIS
 
 #define MLK_CONFIG_FILE "internal/multilevel_config.h"
 
 /* Three instances of mlkem-native for all security levels */
 
 /* Include level-independent code */
 #define MLK_CONFIG_MULTILEVEL_WITH_SHARED
 /* Keep level-independent headers at the end of monobuild file */
 #define MLK_CONFIG_MONOBUILD_KEEP_SHARED_HEADERS
 #define MLK_CONFIG_PARAMETER_SET 512
 #include "internal/mlkem_native_monobuild.c"
 #undef MLK_CONFIG_PARAMETER_SET
 #undef MLK_CONFIG_MULTILEVEL_WITH_SHARED
 
 /* Exclude level-independent code */
 #define MLK_CONFIG_MULTILEVEL_NO_SHARED
 #define MLK_CONFIG_PARAMETER_SET 768
 #include "internal/mlkem_native_monobuild.c"
 #undef MLK_CONFIG_PARAMETER_SET
 /* `#undef` all headers at the and of the monobuild file */
 #undef MLK_CONFIG_MONOBUILD_KEEP_SHARED_HEADERS
 
 #define MLK_CONFIG_PARAMETER_SET 1024
 #include "internal/mlkem_native_monobuild.c"
 #undef MLK_CONFIG_PARAMETER_SET
 
