package crypto

import (
	"crypto/rand"
	"encoding/hex"

	"github.com/google/uuid"
)

func Token(byteLength int) string {
	buf := make([]byte, byteLength)
	if _, err := rand.Read(buf); err != nil {
		panic("crypto/rand is unavailable: " + err.Error())
	}
	return hex.EncodeToString(buf)
}

func NewID() string {
	return uuid.NewString()
}
