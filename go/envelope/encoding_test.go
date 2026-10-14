// SPDX-License-Identifier: BSD-3-Clause
package envelope

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFitsHalf(t *testing.T) {
	for _, test := range []struct {
		value float64
		want  bool
	}{
		{0, true},
		{math.Copysign(0, -1), true},
		{math.Inf(1), true},
		{-8, true},
		{65504, true},
		{65520, false},
		{1 + 0x1p-10, true},
		{1 + 0x1p-11, false},
		{0x1p-14, true},
		{0x1p-14 + 0x1p-24, true},
		{0x1p-24, true},
		{0x1p-25, false},
		{3 * 0x1p-25, false},
		{float64(float32(1.1)), false},
		{-float64(math.MaxFloat32), false},
		{float64(math.SmallestNonzeroFloat32), false},
	} {
		assert.Equal(t, test.want, fitsHalf(test.value), "%g", test.value)
	}
}

func TestDecodeAllRejectsNonShortestHeads(t *testing.T) {
	for _, encoded := range [][]byte{
		{0x18, 0x17},             // 23 in a one-byte argument
		{0x19, 0x00, 0xff},       // 255 in a two-byte argument
		{0x5a, 0, 0, 0xff, 0xff}, // byte-string length 65535 in four bytes
		{0xfa, 0x3f, 0x80, 0, 0}, // 1.0 in single precision
		{0xf8, 0x10},             // simple value 16 in the two-byte form
		{0x81, 0xc6, 0x00},       // a tag below the outermost item
	} {
		_, err := decodeAll(encoded)
		assert.Error(t, err, "% x", encoded)
	}
	for _, encoded := range [][]byte{{0x18, 0x18}, {0xf9, 0x3c, 0x00}, {0xfa, 0x3f, 0x8c, 0xcc, 0xcd}, {0xc6, 0x00}} {
		_, err := decodeAll(encoded)
		assert.NoError(t, err, "% x", encoded)
	}
}
