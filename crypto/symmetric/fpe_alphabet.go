package symmetric

import (
	"errors"

	"golang.org/x/exp/slices"
)

const defaultAlphabetStr = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

var defaultAlphabet, _ = NewAlphabet(defaultAlphabetStr)

type letter struct {
	val rune
	pos int
}

type Alphabet struct {
	def bool

	byPos []rune
	byVal []letter
}

func NewAlphabet(s string) (Alphabet, error) {
	self := Alphabet{
		byPos: []rune(s),
	}

	self.byVal = make([]letter, len(self.byPos))
	for i, v := range self.byPos {
		self.byVal[i] = letter{
			val: v,
			pos: i,
		}
	}
	slices.SortFunc(self.byVal,
		func(a, b letter) int {
			return int(a.val) - int(b.val)
		})

	for i := 1; i < len(self.byVal); i++ {
		if self.byVal[i] == self.byVal[i-1] {
			return Alphabet{}, errors.New("字符集包含重复字符")
		}
	}

	self.def = (len(s) <= len(defaultAlphabetStr)) &&
		(s == defaultAlphabetStr[:len(s)])

	return self, nil
}

func (self *Alphabet) Len() int {
	return len(self.byPos)
}

func (self *Alphabet) IsDef() bool {
	return self.def
}

func (self *Alphabet) PosOf(c rune) int {
	idx, ok := slices.BinarySearchFunc(self.byVal, c,
		func(a letter, b rune) int {
			return int(a.val) - int(b)
		})
	if !ok {
		return -1
	}

	return self.byVal[idx].pos
}

func (self *Alphabet) ValAt(i int) rune {
	return self.byPos[i]
}
