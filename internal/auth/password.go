package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

type Argon2idParams struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

var DefaultArgon2idParams = Argon2idParams{
	Memory:      64 * 1024,
	Iterations:  3,
	Parallelism: 2,
	SaltLength:  16,
	KeyLength:   32,
}

func HashPassword(password string, params Argon2idParams) (string, error) {
	if len(password) < 12 {
		return "", errors.New("password must contain at least 12 characters")
	}

	salt := make([]byte, params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("read random salt: %w", err)
	}

	hash := argon2.IDKey([]byte(password), salt, params.Iterations, params.Memory, params.Parallelism, params.KeyLength)
	encodedSalt := base64.RawStdEncoding.EncodeToString(salt)
	encodedHash := base64.RawStdEncoding.EncodeToString(hash)

	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		params.Memory, params.Iterations, params.Parallelism, encodedSalt, encodedHash), nil
}

func VerifyPassword(password, encodedHash string) (bool, error) {
	params, salt, expectedHash, err := decodeHash(encodedHash)
	if err != nil {
		return false, err
	}

	actualHash := argon2.IDKey([]byte(password), salt, params.Iterations, params.Memory, params.Parallelism, params.KeyLength)
	if subtle.ConstantTimeCompare(actualHash, expectedHash) == 1 {
		return true, nil
	}
	return false, nil
}

func decodeHash(encodedHash string) (Argon2idParams, []byte, []byte, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" {
		return Argon2idParams{}, nil, nil, errors.New("invalid argon2id hash format")
	}

	var params Argon2idParams
	for _, item := range strings.Split(parts[3], ",") {
		kv := strings.SplitN(item, "=", 2)
		if len(kv) != 2 {
			return Argon2idParams{}, nil, nil, errors.New("invalid argon2id parameter")
		}
		value, err := strconv.ParseUint(kv[1], 10, 32)
		if err != nil {
			return Argon2idParams{}, nil, nil, fmt.Errorf("parse argon2id parameter: %w", err)
		}
		switch kv[0] {
		case "m":
			params.Memory = uint32(value)
		case "t":
			params.Iterations = uint32(value)
		case "p":
			params.Parallelism = uint8(value)
		default:
			return Argon2idParams{}, nil, nil, errors.New("unknown argon2id parameter")
		}
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return Argon2idParams{}, nil, nil, fmt.Errorf("decode argon2id salt: %w", err)
	}
	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return Argon2idParams{}, nil, nil, fmt.Errorf("decode argon2id hash: %w", err)
	}
	params.SaltLength = uint32(len(salt))
	params.KeyLength = uint32(len(expectedHash))

	return params, salt, expectedHash, nil
}
