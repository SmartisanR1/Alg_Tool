package gm

import (
	"encoding/hex"
	"strings"
)

func hexUpper(b []byte) string {
	return strings.ToUpper(hex.EncodeToString(b))
}
