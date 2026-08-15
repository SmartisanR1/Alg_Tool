package symmetric

import (
	"crypto/cipher"
	"errors"
	"math"
	"math/big"
)

var cipherIV = [...]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

// common structure used by fpe algorithms
// based on NIST SP 800-38G FF1/FF3-1 reference structure
// with a pluggable block cipher (AES/SM4)
type ffx struct {
	blockMode cipher.BlockMode

	alpha Alphabet

	len struct {
		txt, twk struct {
			min, max int
		}
	}
	twk []byte

	nA, nB, mU, mV, y *big.Int
}

func newFFX(block cipher.Block, twk []byte,
	maxtxt, mintwk, maxtwk, radix int,
	alpha string) (*ffx, error) {
	if block.BlockSize() != 16 {
		return nil, errors.New("块大小必须是16字节")
	}

	if alpha == "" {
		alpha = defaultAlphabetStr
	}

	ralpha := []rune(alpha)
	if radix < 2 || radix > len(ralpha) {
		return nil, errors.New("不支持的基数")
	}
	ralpha = ralpha[:radix]

	mintxt := int(math.Ceil(float64(6) / math.Log10(float64(radix))))
	if mintxt < 2 || mintxt > maxtxt {
		return nil, errors.New("文本长度不符合标准要求")
	}

	if twk == nil {
		twk = make([]byte, 0)
	}

	if mintwk > maxtwk || len(twk) < mintwk ||
		(maxtwk > 0 && len(twk) > maxtwk) {
		return nil, errors.New("Tweak长度不符合要求")
	}

	ctx := new(ffx)
	ctx.blockMode = cipher.NewCBCEncrypter(block, cipherIV[:])
	ctx.alpha, _ = NewAlphabet(string(ralpha))
	ctx.len.txt.min = mintxt
	ctx.len.txt.max = maxtxt
	ctx.len.twk.min = mintwk
	ctx.len.twk.max = maxtwk
	ctx.twk = make([]byte, len(twk))
	copy(ctx.twk[:], twk[:])
	ctx.nA = big.NewInt(0)
	ctx.nB = big.NewInt(0)
	ctx.mU = big.NewInt(0)
	ctx.mV = big.NewInt(0)
	ctx.y = big.NewInt(0)

	return ctx, nil
}

func (ctx *ffx) prf(d, s []byte) error {
	blockSize := ctx.blockMode.BlockSize()
	(ctx.blockMode.(interface{ SetIV([]byte) })).SetIV(cipherIV[:])

	for i := 0; i < len(s); i += blockSize {
		ctx.blockMode.CryptBlocks(d, s[i:i+blockSize])
	}

	return nil
}

func (ctx *ffx) ciph(d, s []byte) error {
	return ctx.prf(d, s[0:16])
}

func BigIntToRunes(alpha *Alphabet, n *big.Int, l int) []rune {
	R := make([]rune, l)

	if alpha.Len() <= defaultAlphabet.Len() {
		s := n.Text(alpha.Len())

		for i := 0; i < len(s); i++ {
			if alpha.IsDef() {
				R[len(s)-i-1] = rune(s[i])
			} else {
				R[len(s)-i-1] = alpha.ValAt(
					defaultAlphabet.PosOf(rune(s[i])))
			}
		}
	} else {
		var r *big.Int = big.NewInt(0)
		var t *big.Int = big.NewInt(int64(alpha.Len()))
		value := new(big.Int).Set(n)

		for i := 0; !value.IsInt64() || value.Int64() != 0; i++ {
			value.DivMod(value, t, r)
			R[i] = alpha.ValAt(int(r.Int64()))
		}
	}

	for i := 0; i < l; i++ {
		if R[i] == 0 {
			R[i] = alpha.ValAt(0)
		}
	}

	reverseRunes(R, R)
	return R
}

func RunesToBigInt(n *big.Int, alpha *Alphabet, s []rune) *big.Int {
	if alpha.Len() <= defaultAlphabet.Len() {
		b := make([]byte, len(s))

		for i := range s {
			if alpha.IsDef() {
				b[i] = byte(s[i])
			} else {
				b[i] = byte(defaultAlphabet.ValAt(
					alpha.PosOf(s[i])))
			}
		}

		n.SetString(string(b), alpha.Len())
	} else {
		var m *big.Int = big.NewInt(1)
		var t *big.Int = big.NewInt(0)

		n.SetInt64(0)

		for _, r := range reverseRunesCopy(s) {
			t.SetInt64(int64(alpha.PosOf(r)))
			t.Mul(t, m)
			n.Add(n, t)

			t.SetInt64(int64(alpha.Len()))
			m.Mul(m, t)
		}
	}

	return n
}

func reverseBytes(d, s []byte) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		d[i], d[j] = s[j], s[i]
	}
	if len(s)%2 == 1 {
		mid := len(s) / 2
		d[mid] = s[mid]
	}
}

func reverseRunes(d, s []rune) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		d[i], d[j] = s[j], s[i]
	}
	if len(s)%2 == 1 {
		mid := len(s) / 2
		d[mid] = s[mid]
	}
}

func reverseRunesCopy(s []rune) []rune {
	d := make([]rune, len(s))
	reverseRunes(d, s)
	return d
}
