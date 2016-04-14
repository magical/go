// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssa

type sparseTreeNode struct {
	child   *Block
	sibling *Block
	parent  *Block

	// Every block has 6 numbers associated with it:
	// entry-1, entry, entry+1, exit-1, and exit, exit+1.
	// entry and exit are conceptually the top of the block (phi functions)
	// entry+1 and exit-1 are conceptually the bottom of the block (ordinary defs)
	// entry-1 and exit+1 are conceptually "just before" the block (conditions flowing in)
	//
	// This simplifies life if we wish to query information about x
	// when x is both an input to and output of a block.
	entry, exit int32
}

const (
	// When used to lookup up definitions in a sparse tree,
	// these adjustments to a block's entry (+adjust) and
	// exit (-adjust) numbers allow a distinction to be made
	// between assignments (typically branch-dependent
	// conditionals) occurring "before" phi functions, the
	// phi functions, and at the bottom of a block.
	ADJUST_BEFORE = -1 // defined before phi
	ADJUST_TOP    = 0  // defined by phi
	ADJUST_BOTTOM = 1  // defined within block
)

// A sparseTree is a tree of Blocks.
// It allows rapid ancestor queries,
// such as whether one block dominates another.
type sparseTree []sparseTreeNode

// newSparseTree creates a sparseTree from a block-to-parent map (array indexed by Block.ID)
func newSparseTree(f *Func, parentOf []*Block) sparseTree {
	t := make(sparseTree, f.NumBlocks())
	for _, b := range f.Blocks {
		n := &t[b.ID]
		if p := parentOf[b.ID]; p != nil {
			n.parent = p
			n.sibling = t[p.ID].child
			t[p.ID].child = b
		}
	}
	t.numberBlock(f.Entry, 1)
	return t
}

// numberBlock assigns entry and exit numbers for b and b's
// children in an in-order walk from a gappy sequence, where n
// is the first number not yet assigned or reserved. N should
// be larger than zero. For each entry and exit number, the
// values one larger and smaller are reserved to indicate
// "strictly above" and "strictly below". numberBlock returns
// the smallest number not yet assigned or reserved (i.e., the
// exit number of the last block visited, plus two, because
// last.exit+1 is a reserved value.)
//
// examples:
//
// single node tree Root, call with n=1
//         entry=2 Root exit=5; returns 7
//
// two node tree, Root->Child, call with n=1
//         entry=2 Root exit=11; returns 13
//         entry=5 Child exit=8
//
// three node tree, Root->(Left, Right), call with n=1
//         entry=2 Root exit=17; returns 19
// entry=5 Left exit=8;  entry=11 Right exit=14
//
// This is the in-order sequence of assigned and reserved numbers
// for the last example:
//   root     left     left      right       right       root
//  1 2e 3 | 4 5e 6 | 7 8x 9 | 10 11e 12 | 13 14x 15 | 16 17x 18

func (t sparseTree) numberBlock(b *Block, n int32) int32 {
	// reserve n for entry-1, assign n+1 to entry
	n++
	t[b.ID].entry = n
	// reserve n+1 for entry+1, n+2 is next free number
	n += 2
	for c := t[b.ID].child; c != nil; c = t[c.ID].sibling {
		n = t.numberBlock(c, n) // preserves n = next free number
	}
	// reserve n for exit-1, assign n+1 to exit
	n++
	t[b.ID].exit = n
	// reserve n+1 for exit+1, n+2 is next free number, returned.
	return n + 2
}

// Sibling returns a sibling of x in the dominator tree (i.e.,
// a node with the same immediate dominator) or nil if there
// are no remaining siblings in the arbitrary but repeatable
// order chosen. Because the Child-Sibling order is used
// to assign entry and exit numbers in the treewalk, those
// numbers are also consistent with this order (i.e.,
// Sibling(x) has entry number larger than x's exit number).
func (t sparseTree) Sibling(x *Block) *Block {
	return t[x.ID].sibling
}

// Child returns a child of x in the dominator tree, or
// nil if there are none. The choice of first child is
// arbitrary but repeatable.
func (t sparseTree) Child(x *Block) *Block {
	return t[x.ID].child
}

// isAncestorEq reports whether x is an ancestor of or equal to y.
func (t sparseTree) isAncestorEq(x, y *Block) bool {
	if x == y {
		return true
	}
	xx := &t[x.ID]
	yy := &t[y.ID]
	return xx.entry <= yy.entry && yy.exit <= xx.exit
}

// isAncestor reports whether x is a strict ancestor of y.
func (t sparseTree) isAncestor(x, y *Block) bool {
	if x == y {
		return false
	}
	xx := &t[x.ID]
	yy := &t[y.ID]
	return xx.entry < yy.entry && yy.exit < xx.exit
}

// maxdomorder returns a value to allow a maximal dominator first sort.  maxdomorder(x) < maxdomorder(y) is true
// if x may dominate y, and false if x cannot dominate y.
func (t sparseTree) maxdomorder(x *Block) int32 {
	return t[x.ID].entry
}