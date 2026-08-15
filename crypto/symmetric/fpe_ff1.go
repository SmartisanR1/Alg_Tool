package symmetric

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"math"
)

// Context structure for FF1 FPE algorithm (NIST SP 800-38G)
type FF1 struct {
	ctx *ffx
}

func newFF1WithBlock(block cipher.Block, keyTweak []byte, mintwk, maxtwk, radix int, alpha string) (*FF1, error) {
	ctx, err := newFFX(block, keyTweak, 1<<32, mintwk, maxtwk, radix, alpha)
	if err != nil {
		return nil, err
	}
	return &FF1{ctx: ctx}, nil
}

// encryption/decryption shared core
func (ff1 *FF1) cipherRunes(X []rune, T []byte, enc bool) ([]rune, error) {
	ctx := ff1.ctx
	radix := ctx.alpha.Len()

	n := len(X)
	u := n / 2
	v := n - u

	b := int(math.Ceil(math.Log2(float64(radix))*float64(v))+7) / 8
	d := 4*((b+3)/4) + 4

	if T == nil {
		T = ctx.twk
	}

	P := make([]byte, 16+((len(T)+b+1+15)/16)*16)
	Q := P[16:]
	R := make([]byte, ((d+15)/16)*16)

	if n < ctx.len.txt.min || n > ctx.len.txt.max {
		return nil, errors.New("文本长度不符合标准要求")
	}
	if len(T) < ctx.len.twk.min || (ctx.len.twk.max > 0 && len(T) > ctx.len.twk.max) {
		return nil, errors.New("Tweak长度不符合要求")
	}

	P[0] = 1
	P[1] = 2
	binary.BigEndian.PutUint32(P[2:6], uint32(radix))
	P[6] = 10
	P[7] = byte(u)
	binary.BigEndian.PutUint32(P[8:12], uint32(n))
	binary.BigEndian.PutUint32(P[12:16], uint32(len(T)))

	copy(Q, bytes.Repeat([]byte{0}, len(Q)))
	copy(Q, T)

	ctx.y.SetUint64(uint64(radix))
	ctx.mU.SetUint64(uint64(u))
	ctx.mU.Exp(ctx.y, ctx.mU, nil)
	ctx.mV.Set(ctx.mU)
	if u != v {
		ctx.mV.Mul(ctx.mV, ctx.y)
	}

	RunesToBigInt(ctx.nA, &ctx.alpha, X[:u])
	RunesToBigInt(ctx.nB, &ctx.alpha, X[u:])
	if !enc {
		ctx.nA, ctx.nB = ctx.nB, ctx.nA
		ctx.mU, ctx.mV = ctx.mV, ctx.mU
	}

	for i := 0; i < 10; i++ {
		if enc {
			Q[len(Q)-b-1] = byte(i)
		} else {
			Q[len(Q)-b-1] = byte(9 - i)
		}

		ctx.nB.FillBytes(Q[len(Q)-b:])
		ctx.prf(R[0:16], P)

		for j := 1; j < len(R)/16; j++ {
			l := j * 16
			w := binary.BigEndian.Uint32(R[12:16])

			binary.BigEndian.PutUint32(R[12:16], w^uint32(j))
			ctx.ciph(R[l:l+16], R[:16])
			binary.BigEndian.PutUint32(R[12:16], uint32(w))
		}

		ctx.y.SetBytes(R[:d])

		if enc {
			ctx.nA.Add(ctx.nA, ctx.y)
		} else {
			ctx.nA.Sub(ctx.nA, ctx.y)
		}

		ctx.nA, ctx.nB = ctx.nB, ctx.nA

		ctx.y.Mod(ctx.nB, ctx.mU)
		ctx.y, ctx.nB = ctx.nB, ctx.y

		ctx.mU, ctx.mV = ctx.mV, ctx.mU
	}

	if !enc {
		ctx.nA, ctx.nB = ctx.nB, ctx.nA
	}

	return append(
			BigIntToRunes(&ctx.alpha, ctx.nA, u),
			BigIntToRunes(&ctx.alpha, ctx.nB, v)...),
		nil
}

func (ff1 *FF1) EncryptRunes(X []rune, T []byte) ([]rune, error) {
	return ff1.cipherRunes(X, T, true)
}

func (ff1 *FF1) DecryptRunes(X []rune, T []byte) ([]rune, error) {
	return ff1.cipherRunes(X, T, false)
}
