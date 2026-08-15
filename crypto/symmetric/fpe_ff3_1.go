package symmetric

import (
	"crypto/cipher"
	"errors"
	"math"
)

// Context structure for the FF3-1 FPE algorithm (NIST SP 800-38G)
type FF3_1 struct {
	ctx *ffx
}

func newFF3_1WithBlock(block cipher.Block, twk []byte, radix int, alpha string) (*FF3_1, error) {
	ctx, err := newFFX(block, twk,
		int(float64(192)/math.Log2(float64(radix))),
		7, 7,
		radix, alpha)
	if err != nil {
		return nil, err
	}

	return &FF3_1{ctx: ctx}, nil
}

func (ff3 *FF3_1) cipherRunes(X []rune, T []byte, enc bool) ([]rune, error) {
	ctx := ff3.ctx

	n := len(X)
	v := n / 2
	u := n - v

	if T == nil {
		T = ctx.twk
	}

	if n < ctx.len.txt.min || n > ctx.len.txt.max {
		return nil, errors.New("文本长度不符合标准要求")
	}
	if len(T) < ctx.len.twk.min || (ctx.len.twk.max > 0 && len(T) > ctx.len.twk.max) {
		return nil, errors.New("Tweak长度不符合要求")
	}

	P := [16]byte{}

	Tw := [2][4]byte{}
	copy(Tw[0][0:3], T[0:3])
	Tw[0][3] = T[3] & 0xf0
	copy(Tw[1][0:3], T[4:7])
	Tw[1][3] = (T[3] & 0x0f) << 4

	ctx.y.SetUint64(uint64(ctx.alpha.Len()))
	ctx.mV.SetUint64(uint64(v))
	ctx.mV.Exp(ctx.y, ctx.mV, nil)
	ctx.mU.Set(ctx.mV)
	if v != u {
		ctx.mU.Mul(ctx.mU, ctx.y)
	}

	A := reverseRunesCopy(X[:u])
	RunesToBigInt(ctx.nA, &ctx.alpha, A)
	B := reverseRunesCopy(X[u:])
	RunesToBigInt(ctx.nB, &ctx.alpha, B)
	if !enc {
		ctx.nA, ctx.nB = ctx.nB, ctx.nA
		ctx.mU, ctx.mV = ctx.mV, ctx.mU

		Tw[0], Tw[1] = Tw[1], Tw[0]
	}

	for i := 1; i <= 8; i++ {
		copy(P[:4], Tw[i%2][:])

		if enc {
			P[3] ^= byte(i - 1)
		} else {
			P[3] ^= byte(8 - i)
		}

		ctx.nB.FillBytes(P[4:16])

		reverseBytes(P[:], P[:])
		ctx.ciph(P[:], P[:])
		reverseBytes(P[:], P[:])

		ctx.y.SetBytes(P[:])
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

	A = BigIntToRunes(&ctx.alpha, ctx.nA, u)
	reverseRunes(A, A)
	B = BigIntToRunes(&ctx.alpha, ctx.nB, v)
	reverseRunes(B, B)

	return append(A, B...), nil
}

func (ff3 *FF3_1) EncryptRunes(X []rune, T []byte) ([]rune, error) {
	return ff3.cipherRunes(X, T, true)
}

func (ff3 *FF3_1) DecryptRunes(X []rune, T []byte) ([]rune, error) {
	return ff3.cipherRunes(X, T, false)
}
