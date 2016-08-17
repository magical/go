// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
Package hmac implements the Keyed-Hash Message Authentication Code (HMAC) as
defined in U.S. Federal Information Processing Standards Publication 198.
An HMAC is a cryptographic hash that uses a key to sign a message.
The receiver verifies the hash by recomputing it using the same key.

Receivers should be careful to use Equal to compare MACs in order to avoid
timing side-channels:

	// CheckMAC reports whether messageMAC is a valid HMAC tag for message.
	func CheckMAC(message, messageMAC, key []byte) bool {
		mac := hmac.New(sha256.New, key)
		mac.Write(message)
		expectedMAC := mac.Sum(nil)
		return hmac.Equal(messageMAC, expectedMAC)
	}
*/
package hmac

import (
	"crypto/subtle"
	"hash"
)

// FIPS 198-1:
// http://csrc.nist.gov/publications/fips/fips198-1/FIPS-198-1_final.pdf

// key is zero padded to the block size of the hash function
// ipad = 0x36 byte repeated for key length
// opad = 0x5c byte repeated for key length
// hmac = H([key ^ opad] H([key ^ ipad] text))

type hashCloner interface {
	hash.Hash
	Clone(hash.Hash) hash.Hash
}

type hmac struct {
	size           int
	blocksize      int
	opad, ipad     []byte
	outer, inner   hash.Hash
	outer0, inner0 hashCloner
}

func (h *hmac) Sum(in []byte) []byte {
	origLen := len(in)
	in = h.inner.Sum(in)
	if h.outer0 != nil {
		h.outer = h.outer0.Clone(h.outer)
	} else {
		h.outer.Reset()
		h.outer.Write(h.opad)
	}
	h.outer.Write(in[origLen:])
	return h.outer.Sum(in[:origLen])
}

func (h *hmac) Write(p []byte) (n int, err error) {
	return h.inner.Write(p)
}

func (h *hmac) Size() int { return h.size }

func (h *hmac) BlockSize() int { return h.blocksize }

func (h *hmac) Reset() {
	if h.inner0 != nil {
		h.inner = h.inner0.Clone(h.inner)
	} else {
		h.inner.Reset()
		h.inner.Write(h.ipad)
	}
}

// New returns a new HMAC hash using the given hash.Hash type and key.
func New(h func() hash.Hash, key []byte) hash.Hash {
	hm := new(hmac)
	hm.outer = h()
	hm.inner = h()
	hm.size = hm.inner.Size()
	hm.blocksize = hm.inner.BlockSize()
	hm.ipad = make([]byte, hm.blocksize)
	hm.opad = make([]byte, hm.blocksize)
	if len(key) > hm.blocksize {
		// If key is too big, hash it.
		hm.outer.Write(key)
		key = hm.outer.Sum(nil)
	}
	copy(hm.ipad, key)
	copy(hm.opad, key)
	for i := range hm.ipad {
		hm.ipad[i] ^= 0x36
	}
	for i := range hm.opad {
		hm.opad[i] ^= 0x5c
	}
	if _, ok := hm.inner.(hashCloner); ok {
		hm.inner0 = h().(hashCloner)
		hm.inner0.Write(hm.ipad)
		hm.outer0 = h().(hashCloner)
		hm.outer0.Write(hm.opad)
		// Don't need these any more;
		// let the gc reclaim them
		hm.ipad = nil
		hm.opad = nil
	}
	hm.Reset()
	return hm
}

// Equal compares two MACs for equality without leaking timing information.
func Equal(mac1, mac2 []byte) bool {
	// We don't have to be constant time if the lengths of the MACs are
	// different as that suggests that a completely different hash function
	// was used.
	return subtle.ConstantTimeCompare(mac1, mac2) == 1
}
