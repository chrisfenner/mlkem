package mlkem

// #cgo CFLAGS: -g -Wall
// #include <stdlib.h>
// #include "mlkem.h"
import "C"
import (
	"unsafe"
)

// mlkem512KeypairDerand wraps mlkem512_keypair_derand for Go callers.
// Safety: panics if pk, sk, and coins are not the proper size.
func mlkem512KeypairDerand(pk []byte, sk []byte, coins []byte) error {
	if ret, err := C.mlkem512_keypair_derand(
		(*C.uint8_t)(unsafe.Pointer(&(pk[0]))),
		(*C.uint8_t)(unsafe.Pointer(&(sk[0]))),
		(*C.uint8_t)(unsafe.Pointer(&(coins[0])))); ret != 0 {
		return err
	}
	return nil
}

// mlkem512EncDerand wraps mlkem512_enc_derand for Go callers.
// Safety: panics if ct, ss, pk, and coins are not the proper size.
func mlkem512EncDerand(ct []byte, ss []byte, pk []byte, coins []byte) error {
	if ret, err := C.mlkem512_enc_derand(
		(*C.uint8_t)(unsafe.Pointer(&(ct[0]))),
		(*C.uint8_t)(unsafe.Pointer(&(ss[0]))),
		(*C.uint8_t)(unsafe.Pointer(&(pk[0]))),
		(*C.uint8_t)(unsafe.Pointer(&(coins[0])))); ret != 0 {
		return err
	}
	return nil
}

// mlkem512Dec wraps mlkem512_dec_derand for Go callers.
// Safety: panics if ss, ct, and sk are not the proper size.
func mlkem512Dec(ss []byte, ct []byte, sk []byte) error {
	if ret, err := C.mlkem512_dec(
		(*C.uint8_t)(unsafe.Pointer(&(ss[0]))),
		(*C.uint8_t)(unsafe.Pointer(&(ct[0]))),
		(*C.uint8_t)(unsafe.Pointer(&(sk[0])))); ret != 0 {
		return err
	}
	return nil
}

// mlkem768KeypairDerand wraps mlkem768_keypair_derand for Go callers.
// Safety: panics if pk, sk, and coins are not the proper size.
func mlkem768KeypairDerand(pk []byte, sk []byte, coins []byte) error {
	if ret, err := C.mlkem768_keypair_derand(
		(*C.uint8_t)(unsafe.Pointer(&(pk[0]))),
		(*C.uint8_t)(unsafe.Pointer(&(sk[0]))),
		(*C.uint8_t)(unsafe.Pointer(&(coins[0])))); ret != 0 {
		return err
	}
	return nil
}

// mlkem768EncDerand wraps mlkem768_enc_derand for Go callers.
// Safety: panics if ct, ss, pk, and coins are not the proper size.
func mlkem768EncDerand(ct []byte, ss []byte, pk []byte, coins []byte) error {
	if ret, err := C.mlkem768_enc_derand(
		(*C.uint8_t)(unsafe.Pointer(&(ct[0]))),
		(*C.uint8_t)(unsafe.Pointer(&(ss[0]))),
		(*C.uint8_t)(unsafe.Pointer(&(pk[0]))),
		(*C.uint8_t)(unsafe.Pointer(&(coins[0])))); ret != 0 {
		return err
	}
	return nil
}

// mlkem768Dec wraps mlkem768_dec_derand for Go callers.
// Safety: panics if ss, ct, and sk are not the proper size.
func mlkem768Dec(ss []byte, ct []byte, sk []byte) error {
	if ret, err := C.mlkem768_dec(
		(*C.uint8_t)(unsafe.Pointer(&(ss[0]))),
		(*C.uint8_t)(unsafe.Pointer(&(ct[0]))),
		(*C.uint8_t)(unsafe.Pointer(&(sk[0])))); ret != 0 {
		return err
	}
	return nil
}

// mlkem1024KeypairDerand wraps mlkem1024_keypair_derand for Go callers.
// Safety: panics if pk, sk, and coins are not the proper size.
func mlkem1024KeypairDerand(pk []byte, sk []byte, coins []byte) error {
	if ret, err := C.mlkem1024_keypair_derand(
		(*C.uint8_t)(unsafe.Pointer(&(pk[0]))),
		(*C.uint8_t)(unsafe.Pointer(&(sk[0]))),
		(*C.uint8_t)(unsafe.Pointer(&(coins[0])))); ret != 0 {
		return err
	}
	return nil
}

// mlkem1024EncDerand wraps mlkem1024_enc_derand for Go callers.
// Safety: panics if ct, ss, pk, and coins are not the proper size.
func mlkem1024EncDerand(ct []byte, ss []byte, pk []byte, coins []byte) error {
	if ret, err := C.mlkem1024_enc_derand(
		(*C.uint8_t)(unsafe.Pointer(&(ct[0]))),
		(*C.uint8_t)(unsafe.Pointer(&(ss[0]))),
		(*C.uint8_t)(unsafe.Pointer(&(pk[0]))),
		(*C.uint8_t)(unsafe.Pointer(&(coins[0])))); ret != 0 {
		return err
	}
	return nil
}

// mlkem1024Dec wraps mlkem1024_dec_derand for Go callers.
// Safety: panics if ss, ct, and sk are not the proper size.
func mlkem1024Dec(ss []byte, ct []byte, sk []byte) error {
	if ret, err := C.mlkem1024_dec(
		(*C.uint8_t)(unsafe.Pointer(&(ss[0]))),
		(*C.uint8_t)(unsafe.Pointer(&(ct[0]))),
		(*C.uint8_t)(unsafe.Pointer(&(sk[0])))); ret != 0 {
		return err
	}
	return nil
}
