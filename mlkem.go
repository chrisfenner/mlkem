// Package mlkem provides Go bindings to the C implementation from https://github.com/pq-code-package/mlkem-native.
package mlkem

import (
	"errors"
	"fmt"
	"io"
)

var (
	ErrBadParameterSet        = errors.New("invalid parameter set")
	ErrMalformedPublicKey     = errors.New("malformed public key")
	ErrMalformedCiphertext    = errors.New("malformed ciphertext")
	ErrInsufficientRandomness = errors.New("insufficient randomness")
)

const (
	mlkemRandomnessBytes   = 32
	mlkemSharedSecretBytes = 32
	mlkem512SecretBytes    = 1632
	mlkem512PubBytes       = 800
	mlkem512CTBytes        = 768
	mlkem768SecretBytes    = 2400
	mlkem768PubBytes       = 1184
	mlkem768CTBytes        = 1088
	mlkem1024SecretBytes   = 3168
	mlkem1024PubBytes      = 1568
	mlkem1024CTBytes       = 1568
)

type ParameterSet int

const (
	invalidParameterSet ParameterSet = iota
	MLKEM512
	MLKEM768
	MLKEM1024
)

// String implements Stringer.
func (parms ParameterSet) String() string {
	switch parms {
	case MLKEM512:
		return "ML-KEM-512"
	case MLKEM768:
		return "ML-KEM-768"
	case MLKEM1024:
		return "ML-KEM-1024"
	default:
		return fmt.Sprintf("unknown parameter set %d", int(parms))
	}
}

// PublicKey represents an ML-KEM public key.
type PublicKey interface {
	// ParameterSet returns the parameter set associated with this key.
	ParameterSet() ParameterSet
	// Encapsulate performs key encapsulation with the given public key, reading randomness from rand.
	Encapsulate(rand io.Reader) (secret []byte, ciphertext []byte, err error)
	// Bytes returns the public key in FIPS-203 format as a byte slice.
	Bytes() []byte
}

// SecretKey represents an ML-KEM secret key.
type SecretKey interface {
	// ParameterSet returns the parameter set associated with this key.
	ParameterSet() ParameterSet
	// Decapsulate recovers the shared secret from the ciphertext.
	Decapsulate(ciphertext []byte) ([]byte, error)
	// PublicKey returns the public key associated with this key.
	PublicKey() PublicKey
	// Bytes returns the expanded secret key in FIPS-203 format as a byte slice.
	Bytes() []byte
	// Seed returns the secret seed as a byte slice.
	Seed() []byte
}

type mlkem512PublicKey [mlkem512PubBytes]byte

// ParameterSet implements PublicKey.
func (_ *mlkem512PublicKey) ParameterSet() ParameterSet {
	return MLKEM512
}

// Encapsulate implements PublicKey.
func (pk *mlkem512PublicKey) Encapsulate(rand io.Reader) (secret []byte, ciphertext []byte, err error) {
	randomness := make([]byte, mlkemRandomnessBytes)
	n, err := rand.Read(randomness)
	if err != nil {
		return nil, nil, err
	}
	if n != len(randomness) {
		return nil, nil, fmt.Errorf("%w: only read %d bytes (needed %d)", ErrInsufficientRandomness, n, len(randomness))
	}

	secret = make([]byte, mlkemSharedSecretBytes)
	ciphertext = make([]byte, mlkem512CTBytes)

	if err := mlkem512EncDerand(ciphertext, secret, pk[:], randomness); err != nil {
		return nil, nil, err
	}
	return secret, ciphertext, nil
}

// Bytes implements PublicKey.
func (pk *mlkem512PublicKey) Bytes() []byte {
	result := make([]byte, len(pk))
	copy(result, pk[:])
	return result
}

type mlkem512SecretKey struct {
	seed [2 * mlkemRandomnessBytes]byte
	pk   *mlkem512PublicKey
	sk   [mlkem512SecretBytes]byte
}

// ParameterSet implements SecretKey.
func (_ *mlkem512SecretKey) ParameterSet() ParameterSet {
	return MLKEM512
}

// Decapsulate implements SecretKey.
func (sk *mlkem512SecretKey) Decapsulate(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) != mlkem512CTBytes {
		return nil, fmt.Errorf("%w: ciphertext was %d bytes (needed %d)", ErrMalformedCiphertext, len(ciphertext), mlkem512CTBytes)
	}

	secret := make([]byte, mlkemSharedSecretBytes)

	if err := mlkem512Dec(secret, ciphertext, sk.sk[:]); err != nil {
		return nil, err
	}

	return secret, nil
}

// PublicKey implements SecretKey.
func (sk *mlkem512SecretKey) PublicKey() PublicKey {
	return sk.pk
}

// Bytes implements SecretKey.
func (sk *mlkem512SecretKey) Bytes() []byte {
	result := make([]byte, len(sk.sk))
	copy(result, sk.sk[:])
	return result
}

// Seed implements SecretKey.
func (sk *mlkem512SecretKey) Seed() []byte {
	result := make([]byte, len(sk.seed))
	copy(result, sk.seed[:])
	return result
}

type mlkem768PublicKey [mlkem768PubBytes]byte

// ParameterSet implements PublicKey.
func (_ *mlkem768PublicKey) ParameterSet() ParameterSet {
	return MLKEM768
}

// Encapsulate implements PublicKey.
func (pk *mlkem768PublicKey) Encapsulate(rand io.Reader) (secret []byte, ciphertext []byte, err error) {
	randomness := make([]byte, mlkemRandomnessBytes)
	n, err := rand.Read(randomness)
	if err != nil {
		return nil, nil, err
	}
	if n != len(randomness) {
		return nil, nil, fmt.Errorf("%w: only read %d bytes (needed %d)", ErrInsufficientRandomness, n, len(randomness))
	}

	secret = make([]byte, mlkemSharedSecretBytes)
	ciphertext = make([]byte, mlkem768CTBytes)

	if err := mlkem768EncDerand(ciphertext, secret, pk[:], randomness); err != nil {
		return nil, nil, err
	}
	return secret, ciphertext, nil
}

// Bytes implements PublicKey.
func (pk *mlkem768PublicKey) Bytes() []byte {
	result := make([]byte, len(pk))
	copy(result, pk[:])
	return result
}

type mlkem768SecretKey struct {
	seed [2 * mlkemRandomnessBytes]byte
	pk   *mlkem768PublicKey
	sk   [mlkem768SecretBytes]byte
}

// ParameterSet implements SecretKey.
func (_ *mlkem768SecretKey) ParameterSet() ParameterSet {
	return MLKEM768
}

// Decapsulate implements SecretKey.
func (sk *mlkem768SecretKey) Decapsulate(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) != mlkem768CTBytes {
		return nil, fmt.Errorf("%w: ciphertext was %d bytes (needed %d)", ErrMalformedCiphertext, len(ciphertext), mlkem768CTBytes)
	}

	secret := make([]byte, mlkemSharedSecretBytes)

	if err := mlkem768Dec(secret, ciphertext, sk.sk[:]); err != nil {
		return nil, err
	}

	return secret, nil
}

// PublicKey implements SecretKey.
func (sk *mlkem768SecretKey) PublicKey() PublicKey {
	return sk.pk
}

// Bytes implements SecretKey.
func (sk *mlkem768SecretKey) Bytes() []byte {
	result := make([]byte, len(sk.sk))
	copy(result, sk.sk[:])
	return result
}

// Seed implements SecretKey.
func (sk *mlkem768SecretKey) Seed() []byte {
	result := make([]byte, len(sk.seed))
	copy(result, sk.seed[:])
	return result
}

type mlkem1024PublicKey [mlkem1024PubBytes]byte

// ParameterSet implements PublicKey.
func (_ *mlkem1024PublicKey) ParameterSet() ParameterSet {
	return MLKEM1024
}

// Encapsulate implements PublicKey.
func (pk *mlkem1024PublicKey) Encapsulate(rand io.Reader) (secret []byte, ciphertext []byte, err error) {
	randomness := make([]byte, mlkemRandomnessBytes)
	n, err := rand.Read(randomness)
	if err != nil {
		return nil, nil, err
	}
	if n != len(randomness) {
		return nil, nil, fmt.Errorf("%w: only read %d bytes (needed %d)", ErrInsufficientRandomness, n, len(randomness))
	}

	secret = make([]byte, mlkemSharedSecretBytes)
	ciphertext = make([]byte, mlkem1024CTBytes)

	if err := mlkem1024EncDerand(ciphertext, secret, pk[:], randomness); err != nil {
		return nil, nil, err
	}
	return secret, ciphertext, nil
}

// Bytes implements PublicKey.
func (pk *mlkem1024PublicKey) Bytes() []byte {
	result := make([]byte, len(pk))
	copy(result, pk[:])
	return result
}

type mlkem1024SecretKey struct {
	seed [2 * mlkemRandomnessBytes]byte
	pk   *mlkem1024PublicKey
	sk   [mlkem1024SecretBytes]byte
}

// ParameterSet implements SecretKey.
func (_ *mlkem1024SecretKey) ParameterSet() ParameterSet {
	return MLKEM1024
}

// Decapsulate implements SecretKey.
func (sk *mlkem1024SecretKey) Decapsulate(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) != mlkem1024CTBytes {
		return nil, fmt.Errorf("%w: ciphertext was %d bytes (needed %d)", ErrMalformedCiphertext, len(ciphertext), mlkem1024CTBytes)
	}

	secret := make([]byte, mlkemSharedSecretBytes)

	if err := mlkem1024Dec(secret, ciphertext, sk.sk[:]); err != nil {
		return nil, err
	}

	return secret, nil
}

// PublicKey implements SecretKey.
func (sk *mlkem1024SecretKey) PublicKey() PublicKey {
	return sk.pk
}

// Bytes implements SecretKey.
func (sk *mlkem1024SecretKey) Bytes() []byte {
	result := make([]byte, len(sk.sk))
	copy(result, sk.sk[:])
	return result
}

// Seed implements SecretKey.
func (sk *mlkem1024SecretKey) Seed() []byte {
	result := make([]byte, len(sk.seed))
	copy(result, sk.seed[:])
	return result
}

func importPublicKey512(pk []byte) (PublicKey, error) {
	if len(pk) != mlkem512PubBytes {
		return nil, fmt.Errorf("%w: %d bytes (expected %d)", ErrMalformedPublicKey, len(pk), mlkem512PubBytes)
	}
	var result mlkem512PublicKey
	copy(result[:], pk)
	return &result, nil
}

func importPublicKey768(pk []byte) (PublicKey, error) {
	if len(pk) != mlkem768PubBytes {
		return nil, fmt.Errorf("%w: %d bytes (expected %d)", ErrMalformedPublicKey, len(pk), mlkem768PubBytes)
	}
	var result mlkem768PublicKey
	copy(result[:], pk)
	return &result, nil
}

func importPublicKey1024(pk []byte) (PublicKey, error) {
	if len(pk) != mlkem1024PubBytes {
		return nil, fmt.Errorf("%w: %d bytes (expected %d)", ErrMalformedPublicKey, len(pk), mlkem1024PubBytes)
	}
	var result mlkem1024PublicKey
	copy(result[:], pk)
	return &result, nil
}

// ImportPublicKey imports the given public key.
func (parms ParameterSet) ImportPublicKey(pk []byte) (PublicKey, error) {
	switch parms {
	case MLKEM512:
		return importPublicKey512(pk)
	case MLKEM768:
		return importPublicKey768(pk)
	case MLKEM1024:
		return importPublicKey1024(pk)
	default:
		return nil, fmt.Errorf("%w: %d", ErrBadParameterSet, parms)
	}
}

func generateKeypair512(dz []byte) (SecretKey, error) {
	var pk mlkem512PublicKey
	var result mlkem512SecretKey

	if err := mlkem512KeypairDerand(pk[:], result.sk[:], dz); err != nil {
		return nil, err
	}

	copy(result.seed[:], dz)
	result.pk = &pk
	return &result, nil
}

func generateKeypair768(dz []byte) (SecretKey, error) {
	var pk mlkem768PublicKey
	var result mlkem768SecretKey

	if err := mlkem768KeypairDerand(pk[:], result.sk[:], dz); err != nil {
		return nil, err
	}

	copy(result.seed[:], dz)
	result.pk = &pk
	return &result, nil
}

func generateKeypair1024(dz []byte) (SecretKey, error) {
	var pk mlkem1024PublicKey
	var result mlkem1024SecretKey

	if err := mlkem1024KeypairDerand(pk[:], result.sk[:], dz); err != nil {
		return nil, err
	}

	copy(result.seed[:], dz)
	result.pk = &pk
	return &result, nil
}

// GenerateKeypair generates a keypair, reading the seed from rand.
func (parms ParameterSet) GenerateKeypair(rand io.Reader) (SecretKey, error) {
	dz := make([]byte, 2*mlkemRandomnessBytes)
	n, err := rand.Read(dz)
	if err != nil {
		return nil, err
	}
	if n != 2*mlkemRandomnessBytes {
		return nil, fmt.Errorf("%w: only read %d bytes (needed %d)", ErrInsufficientRandomness, n, len(dz))
	}

	switch parms {
	case MLKEM512:
		return generateKeypair512(dz)
	case MLKEM768:
		return generateKeypair768(dz)
	case MLKEM1024:
		return generateKeypair1024(dz)
	default:
		return nil, fmt.Errorf("%w: %d", ErrBadParameterSet, parms)
	}
}
