//go:build ignore

// This program generates the NEON kernels in guts/compress_arm64.s. Unlike
// gen.go, it emits assembly text directly, since avo does not support arm64.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
)

// Register allocation, common to all kernels:
//
//	V0-V15   state; lane j of Vi is word i of node j
//	V16-V19  message words (and transpose scratch)
//	V20-V23  rotation temporaries (and transpose scratch)
//	V31      byte shuffle that rotates each word right by 8
//
// The transposed message lives on the stack, so that the message permutation
// between rounds costs nothing: each round simply reads different offsets.
const (
	msgOff   = 16  // 2x16 message vectors
	cOff     = 528 // 2x4 state vectors
	ctrLoOff = 656 // low words of each lane's counter
	ctrHiOff = 688 // high words of each lane's counter
	frame    = 736
)

var iv = [4]uint32{0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A}

var buf bytes.Buffer

func op(format string, args ...any) { fmt.Fprintf(&buf, "\t"+format+"\n", args...) }
func label(name string)             { fmt.Fprintf(&buf, "\n%s:\n", name) }
func comment(format string, args ...any) {
	fmt.Fprintf(&buf, "\n\t// "+format+"\n", args...)
}

func text(name string, argSize int, sig string) {
	fmt.Fprintf(&buf, "\n// func %s%s\nTEXT ·%s(SB), 0, $%d-%d\n", name, sig, name, frame, argSize)
}

func msg(i int) string { return fmt.Sprintf("%d(RSP)", msgOff+16*i) }

// broadcast sets every lane of Vv to the word in the general-purpose register.
func broadcast(reg string, v int) { op("VDUP %s, V%d.S4", reg, v) }

// broadcastWords sets Vfirst... to the n words at ptr.
func broadcastWords(ptr string, n, first int) {
	for i := range n {
		op("MOVWU %d(%s), R9", 4*i, ptr)
		broadcast("R9", first+i)
	}
}

func loadIV() {
	for i, w := range iv {
		op("MOVD $0x%08X, R9", w)
		broadcast("R9", 8+i)
	}
}

// storeCounters stores the low and high words of counter+j, for each lane j.
func storeCounters(counter string) {
	for j := 0; j < 4; j++ {
		op("MOVW %s, %d(RSP)", counter, ctrLoOff+4*j)
		op("LSR $32, %s, R10", counter)
		op("MOVW R10, %d(RSP)", ctrHiOff+4*j)
		op("ADD $1, %s", counter)
	}
}

// transpose transposes the 4x4 matrix in V(src)..V(src+3), using V16-V19 as
// scratch, and returns the registers holding the result.
func transpose(src int) [4]int { return transposeWith(src, 16) }

func transposeWith(src, t int) (dst [4]int) {
	op("VZIP1 V%d.S4, V%d.S4, V%d.S4", src+1, src, t)
	op("VZIP2 V%d.S4, V%d.S4, V%d.S4", src+1, src, t+1)
	op("VZIP1 V%d.S4, V%d.S4, V%d.S4", src+3, src+2, t+2)
	op("VZIP2 V%d.S4, V%d.S4, V%d.S4", src+3, src+2, t+3)
	dst = [4]int{src, src + 1, src + 2, src + 3}
	op("VZIP1 V%d.D2, V%d.D2, V%d.D2", t+2, t, dst[0])
	op("VZIP2 V%d.D2, V%d.D2, V%d.D2", t+2, t, dst[1])
	op("VZIP1 V%d.D2, V%d.D2, V%d.D2", t+3, t+1, dst[2])
	op("VZIP2 V%d.D2, V%d.D2, V%d.D2", t+3, t+1, dst[3])
	return
}

// loadMessage loads a block from each of the four rows and stores the
// transposed message on the stack.
func loadMessage(rows [4]string) {
	for q := range 4 {
		for j, r := range rows {
			op("FMOVQ %d(%s), F%d", 16*q, r, 20+j)
		}
		for i, v := range transpose(20) {
			op("FMOVQ F%d, %s", v, msg(4*q+i))
		}
	}
}

// storeRows transposes V(src)..V(src+3) and stores row j at off+j*stride(ptr).
func storeRows(src int, ptr string, off, stride int) {
	for j, v := range transpose(src) {
		op("FMOVQ F%d, %d(%s)", v, off+j*stride, ptr)
	}
}

// rounds performs the 7 rounds on the state in V0-V15, using the message on
// the stack. The rounds are a subroutine, rather than being inlined into each
// kernel, since the call costs nothing measurable and the rounds make up most
// of the code.
func rounds() { op("CALL rounds<>(SB)") }

func genRounds() {
	// NOTE: the subroutine has no frame of its own, so its stack offsets are
	// the same as its caller's.
	fmt.Fprint(&buf, "\nTEXT rounds<>(SB), NOSPLIT|NOFRAME, $0-0\n")
	type g struct{ a, b, c, d int }
	steps := [2][4]g{
		{{0, 4, 8, 12}, {1, 5, 9, 13}, {2, 6, 10, 14}, {3, 7, 11, 15}}, // columns
		{{0, 5, 10, 15}, {1, 6, 11, 12}, {2, 7, 8, 13}, {3, 4, 9, 14}}, // diagonals
	}
	m := [16]int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	// half performs half of G for four independent sets of words at once.
	half := func(gs [4]g, words [4]int, rotD func(d int), rotB int) {
		stages := []func(k int, g g){
			func(k int, g g) { op("FMOVQ %s, F%d", msg(words[k]), 16+k) },
			// NOTE: the message is added before b, since b is the last of
			// the three to become available.
			func(k int, g g) { op("VADD V%d.S4, V%d.S4, V%d.S4", 16+k, g.a, g.a) },
			func(k int, g g) { op("VADD V%d.S4, V%d.S4, V%d.S4", g.b, g.a, g.a) },
			func(k int, g g) { op("VEOR V%d.B16, V%d.B16, V%d.B16", g.a, g.d, g.d) },
			func(k int, g g) { rotD(g.d) },
			func(k int, g g) { op("VADD V%d.S4, V%d.S4, V%d.S4", g.d, g.c, g.c) },
			func(k int, g g) { op("VEOR V%d.B16, V%d.B16, V%d.B16", g.c, g.b, 20+k) },
			func(k int, g g) { op("VSHL $%d, V%d.S4, V%d.S4", 32-rotB, 20+k, g.b) },
			func(k int, g g) { op("VSRI $%d, V%d.S4, V%d.S4", rotB, 20+k, g.b) },
		}
		// each stage is emitted for all four before moving on to the next
		for _, stage := range stages {
			for k, g := range gs {
				stage(k, g)
			}
		}
	}
	rot16 := func(d int) { op("VREV32 V%d.H8, V%d.H8", d, d) }
	rot8 := func(d int) { op("VTBL V31.B16, [V%d.B16], V%d.B16", d, d) }

	for r := range 7 {
		comment("round %d", r+1)
		for i, gs := range steps {
			w := m[8*i:]
			half(gs, [4]int{w[0], w[2], w[4], w[6]}, rot16, 12)
			half(gs, [4]int{w[1], w[3], w[5], w[7]}, rot8, 7)
		}
		m = [16]int{
			m[2], m[6], m[3], m[10],
			m[7], m[0], m[4], m[13],
			m[1], m[11], m[12], m[5],
			m[9], m[14], m[15], m[8],
		}
	}
	op("RET")
}

func prelude() {
	fmt.Fprint(&buf, `// Code generated by avo/gen_arm64.go. DO NOT EDIT.

#include "textflag.h"

DATA rot8<>+0(SB)/8, $0x0407060500030201
DATA rot8<>+8(SB)/8, $0x0C0F0E0D080B0A09
GLOBL rot8<>(SB), RODATA|NOPTR, $16
`)
}

func loadRot8() {
	op("MOVD $rot8<>(SB), R9")
	op("VLD1 (R9), [V31.B16]")
}

func genCompressChunks() {
	text("compressChunksNEON", 36, "(cvs *[4][8]uint32, buf *[4096]byte, key *[8]uint32, counter uint64, flags uint32)")
	op("MOVD cvs+0(FP), R0")
	op("MOVD buf+8(FP), R1")
	op("MOVD key+16(FP), R2")
	op("MOVD counter+24(FP), R3")
	op("MOVWU flags+32(FP), R4")
	loadRot8()
	storeCounters("R3")
	broadcastWords("R2", 8, 0)
	comment("R1, R5, R6, R7 point to the current block of each chunk")
	op("ADD $1024, R1, R5")
	op("ADD $2048, R1, R6")
	op("ADD $3072, R1, R7")
	op("MOVD $0, R8")

	label("loop")
	loadMessage([4]string{"R1", "R5", "R6", "R7"})
	comment("the first block is flagged as the chunk start, the last as the chunk end")
	op("MOVW R4, R10")
	op("CBNZ R8, notfirst")
	op("ORR $1, R10")
	label("notfirst")
	op("CMP $15, R8")
	op("BNE notlast")
	op("ORR $2, R10")
	label("notlast")
	loadIV()
	op("FMOVQ %d(RSP), F12", ctrLoOff)
	op("FMOVQ %d(RSP), F13", ctrHiOff)
	op("MOVD $64, R9")
	broadcast("R9", 14)
	broadcast("R10", 15)

	rounds()

	comment("finalize chaining values")
	for i := range 8 {
		op("VEOR V%d.B16, V%d.B16, V%d.B16", i+8, i, i)
	}
	for _, r := range []string{"R1", "R5", "R6", "R7"} {
		op("ADD $64, %s", r)
	}
	op("ADD $1, R8")
	op("CMP $16, R8")
	op("BNE loop")

	comment("store transposed chaining values")
	storeRows(0, "R0", 0, 32)
	storeRows(4, "R0", 16, 32)
	op("RET")
}

func genCompressParents() {
	text("compressParentsNEON", 28, "(parents *[4][8]uint32, cvs *[8][8]uint32, key *[8]uint32, flags uint32)")
	op("MOVD parents+0(FP), R0")
	op("MOVD cvs+8(FP), R1")
	op("MOVD key+16(FP), R2")
	op("MOVWU flags+24(FP), R4")
	loadRot8()
	comment("each pair of chaining values is one block")
	op("ADD $64, R1, R5")
	op("ADD $128, R1, R6")
	op("ADD $192, R1, R7")
	loadMessage([4]string{"R1", "R5", "R6", "R7"})
	broadcastWords("R2", 8, 0)
	loadIV()
	comment("parents have no counter")
	op("VEOR V12.B16, V12.B16, V12.B16")
	op("VEOR V13.B16, V13.B16, V13.B16")
	op("MOVD $64, R9")
	broadcast("R9", 14)
	op("ORR $4, R4")
	broadcast("R4", 15)

	rounds()

	comment("finalize and store transposed chaining values")
	for i := 0; i < 8; i++ {
		op("VEOR V%d.B16, V%d.B16, V%d.B16", i+8, i, i)
	}
	storeRows(0, "R0", 0, 32)
	storeRows(4, "R0", 16, 32)
	op("RET")
}

// The scalar routines compress one node at a time, using the general-purpose
// registers. NEON is slower than this for a single node, because NEON
// instructions take longer to execute and a single node offers little to do
// in parallel.
//
// Register allocation:
//
//	R0-R15   state
//	R16      counter
//	R19      message
//	R24-R25  message words

func scalarText(name string, argSize int, sig string) {
	fmt.Fprintf(&buf, "\n// func %s%s\nTEXT ·%s(SB), 0, $16-%d\n", name, sig, name, argSize)
}

// scalarInit sets the last 8 words of the state.
func scalarInit(blockLen, flags string) {
	for i, w := range iv {
		op("MOVD $0x%08X, R%d", w, 8+i)
	}
	op("MOVWU R16, R12")
	op("LSR $32, R16, R13")
	op("MOVWU %s, R14", blockLen)
	op("MOVWU %s, R15", flags)
}

func genScalarRounds() {
	fmt.Fprint(&buf, "\nTEXT scalarRounds<>(SB), NOSPLIT|NOFRAME, $0-0\n")
	type g struct{ a, b, c, d int }
	steps := [2][4]g{
		{{0, 4, 8, 12}, {1, 5, 9, 13}, {2, 6, 10, 14}, {3, 7, 11, 15}}, // columns
		{{0, 5, 10, 15}, {1, 6, 11, 12}, {2, 7, 8, 13}, {3, 4, 9, 14}}, // diagonals
	}
	m := [16]int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	half := func(g g, word, tmp, rotD, rotB int) {
		op("MOVWU %d(R19), R%d", 4*word, tmp)
		op("ADDW R%d, R%d", tmp, g.a)
		op("ADDW R%d, R%d", g.b, g.a)
		op("EORW R%d, R%d", g.a, g.d)
		op("RORW $%d, R%d, R%d", rotD, g.d, g.d)
		op("ADDW R%d, R%d", g.d, g.c)
		op("EORW R%d, R%d", g.c, g.b)
		op("RORW $%d, R%d, R%d", rotB, g.b, g.b)
	}
	for r := range 7 {
		comment("round %d", r+1)
		for i, gs := range steps {
			for k, g := range gs {
				half(g, m[8*i+2*k], 24, 16, 12)
			}
			for k, g := range gs {
				half(g, m[8*i+2*k+1], 25, 8, 7)
			}
		}
		m = [16]int{
			m[2], m[6], m[3], m[10],
			m[7], m[0], m[4], m[13],
			m[1], m[11], m[12], m[5],
			m[9], m[14], m[15], m[8],
		}
	}
	op("RET")
}

func genCompressNodeScalar() {
	scalarText("compressNodeARM64", 40, "(out *[16]uint32, cv *[8]uint32, block *[16]uint32, counter uint64, blockLen uint32, flags uint32)")
	op("MOVD out+0(FP), R21")
	op("MOVD cv+8(FP), R20")
	op("MOVD block+16(FP), R19")
	op("MOVD counter+24(FP), R16")
	op("MOVWU blockLen+32(FP), R22")
	op("MOVWU flags+36(FP), R23")
	for i := range 8 {
		op("MOVWU %d(R20), R%d", 4*i, i)
	}
	scalarInit("R22", "R23")
	op("CALL scalarRounds<>(SB)")
	comment("finalize")
	for i := range 8 {
		op("EORW R%d, R%d", 8+i, i)
		op("MOVWU %d(R20), R24", 4*i)
		op("EORW R24, R%d", 8+i)
	}
	for i := range 16 {
		op("MOVW R%d, %d(R21)", i, 4*i)
	}
	op("RET")
}

func genCompressChunkBlocksScalar() {
	scalarText("compressChunkBlocksARM64", 36, "(cv *[8]uint32, blocks *byte, n uint64, counter uint64, flags uint32)")
	op("MOVD cv+0(FP), R20")
	op("MOVD blocks+8(FP), R19")
	op("MOVD n+16(FP), R21")
	op("MOVD counter+24(FP), R16")
	op("MOVWU flags+32(FP), R23")
	for i := range 8 {
		op("MOVWU %d(R20), R%d", 4*i, i)
	}
	comment("the first block is flagged as the chunk start")
	op("ORR $1, R23, R22")
	op("MOVD $64, R26")

	label("loop")
	scalarInit("R26", "R22")
	op("CALL scalarRounds<>(SB)")
	comment("finalize chaining value")
	for i := range 8 {
		op("EORW R%d, R%d", 8+i, i)
	}
	op("MOVWU R23, R22")
	op("ADD $64, R19")
	op("SUBS $1, R21")
	op("BNE loop")

	for i := range 8 {
		op("MOVW R%d, %d(R20)", i, 4*i)
	}
	op("RET")
}

// The 8-way kernels interleave two independent sets of four nodes. A 4-way
// compression is limited by its dependency chain, not by the number of
// instructions the CPU can execute at once, so the second set is nearly free.
//
// Register allocation:
//
//	V0-V11   set 0: words 0-7 and 12-15
//	V12-V23  set 1: words 0-7 and 12-15
//	V24-V27  temporaries
//	V31      byte shuffle that rotates each word right by 8
//
// Words 8-11 of each set live on the stack. They are only read once per
// half-round, long after they are written, so the round trip is free.

func reg8(s, i int) int {
	if i >= 12 {
		i -= 4
	}
	return 12*s + i
}
func msg8(s, i int) string { return fmt.Sprintf("%d(RSP)", msgOff+16*(16*s+i)) }
func c8(s, i int) string   { return fmt.Sprintf("%d(RSP)", cOff+16*(4*s+i)) }

func storeCounters8(counter string) {
	for j := range 8 {
		op("MOVW %s, %d(RSP)", counter, ctrLoOff+4*j)
		op("LSR $32, %s, R10", counter)
		op("MOVW R10, %d(RSP)", ctrHiOff+4*j)
		op("ADD $1, %s", counter)
	}
}

// loadMessage8 loads a block from each of 8 rows, stride bytes apart.
func loadMessage8(ptr string, stride int) {
	for s := range 2 {
		for q := range 4 {
			for j := range 4 {
				op("FMOVQ %d(%s), F%d", stride*(4*s+j)+16*q, ptr, 24+j)
			}
			for i, v := range transposeWith(24, 8) {
				op("FMOVQ F%d, %s", v, msg8(s, 4*q+i))
			}
		}
	}
}

func broadcastKey8(ptr string) {
	for i := range 8 {
		op("MOVWU %d(%s), R9", 4*i, ptr)
		broadcast("R9", reg8(0, i))
		broadcast("R9", reg8(1, i))
	}
}

// init8 sets the last 8 words of both states.
func init8(counters bool, blockLen, flags string) {
	for i, w := range iv {
		op("MOVD $0x%08X, R9", w)
		broadcast("R9", 24)
		op("FMOVQ F24, %s", c8(0, i))
		op("FMOVQ F24, %s", c8(1, i))
	}
	for s := range 2 {
		if counters {
			op("FMOVQ %d(RSP), F%d", ctrLoOff+16*s, reg8(s, 12))
			op("FMOVQ %d(RSP), F%d", ctrHiOff+16*s, reg8(s, 13))
		} else {
			op("VEOR V%d.B16, V%d.B16, V%d.B16", reg8(s, 12), reg8(s, 12), reg8(s, 12))
			op("VEOR V%d.B16, V%d.B16, V%d.B16", reg8(s, 13), reg8(s, 13), reg8(s, 13))
		}
		broadcast(blockLen, reg8(s, 14))
		broadcast(flags, reg8(s, 15))
	}
}

func finalize8() {
	for s := range 2 {
		for i := range 4 {
			op("FMOVQ %s, F24", c8(s, i))
			op("VEOR V24.B16, V%d.B16, V%d.B16", reg8(s, i), reg8(s, i))
			op("VEOR V%d.B16, V%d.B16, V%d.B16", reg8(s, 12+i), reg8(s, 4+i), reg8(s, 4+i))
		}
	}
}

func storeRows8(src int, ptr string, off, stride int) {
	for j, v := range transposeWith(src, 24) {
		op("FMOVQ F%d, %d(%s)", v, off+j*stride, ptr)
	}
}

func storeCVs8() {
	for s := range 2 {
		storeRows8(reg8(s, 0), "R0", 128*s, 32)
		storeRows8(reg8(s, 4), "R0", 128*s+16, 32)
	}
}

func genRounds8() {
	fmt.Fprint(&buf, "\nTEXT rounds8<>(SB), NOSPLIT|NOFRAME, $0-0\n")
	type g struct{ a, b, c, d int }
	steps := [2][4]g{
		{{0, 4, 8, 12}, {1, 5, 9, 13}, {2, 6, 10, 14}, {3, 7, 11, 15}}, // columns
		{{0, 5, 10, 15}, {1, 6, 11, 12}, {2, 7, 8, 13}, {3, 4, 9, 14}}, // diagonals
	}
	m := [16]int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	// NOTE: unlike the 4-way rounds, interleaving the instructions of
	// independent Gs is slower here.
	half := func(s int, g g, word int, rotD func(d int), rotB int) {
		a, b, c, d := reg8(s, g.a), reg8(s, g.b), c8(s, g.c-8), reg8(s, g.d)
		op("FMOVQ %s, F24", msg8(s, word))
		op("VADD V24.S4, V%d.S4, V%d.S4", a, a)
		op("VADD V%d.S4, V%d.S4, V%d.S4", b, a, a)
		op("VEOR V%d.B16, V%d.B16, V%d.B16", a, d, d)
		rotD(d)
		op("FMOVQ %s, F25", c)
		op("VADD V%d.S4, V25.S4, V25.S4", d)
		op("FMOVQ F25, %s", c)
		op("VEOR V25.B16, V%d.B16, V25.B16", b)
		op("VSHL $%d, V25.S4, V%d.S4", 32-rotB, b)
		op("VSRI $%d, V25.S4, V%d.S4", rotB, b)
	}
	rot16 := func(d int) { op("VREV32 V%d.H8, V%d.H8", d, d) }
	rot8 := func(d int) { op("VTBL V31.B16, [V%d.B16], V%d.B16", d, d) }

	for r := range 7 {
		comment("round %d", r+1)
		for i, gs := range steps {
			for s := range 2 {
				for k, g := range gs {
					half(s, g, m[8*i+2*k], rot16, 12)
				}
			}
			for s := range 2 {
				for k, g := range gs {
					half(s, g, m[8*i+2*k+1], rot8, 7)
				}
			}
		}
		m = [16]int{
			m[2], m[6], m[3], m[10],
			m[7], m[0], m[4], m[13],
			m[1], m[11], m[12], m[5],
			m[9], m[14], m[15], m[8],
		}
	}
	op("RET")
}

func genCompressChunks8() {
	text("compressChunks8NEON", 36, "(cvs *[8][8]uint32, buf *[8192]byte, key *[8]uint32, counter uint64, flags uint32)")
	op("MOVD cvs+0(FP), R0")
	op("MOVD buf+8(FP), R1")
	op("MOVD key+16(FP), R2")
	op("MOVD counter+24(FP), R3")
	op("MOVWU flags+32(FP), R4")
	loadRot8()
	storeCounters8("R3")
	broadcastKey8("R2")
	op("MOVD $0, R8")
	op("MOVD $64, R11")

	label("loop")
	loadMessage8("R1", 1024)
	comment("the first block is flagged as the chunk start, the last as the chunk end")
	op("MOVW R4, R10")
	op("CBNZ R8, notfirst")
	op("ORR $1, R10")
	label("notfirst")
	op("CMP $15, R8")
	op("BNE notlast")
	op("ORR $2, R10")
	label("notlast")
	init8(true, "R11", "R10")
	op("CALL rounds8<>(SB)")
	comment("finalize chaining values")
	finalize8()
	op("ADD $64, R1")
	op("ADD $1, R8")
	op("CMP $16, R8")
	op("BNE loop")

	comment("store transposed chaining values")
	storeCVs8()
	op("RET")
}

func genCompressParents8() {
	text("compressParents8NEON", 28, "(parents *[8][8]uint32, cvs *[16][8]uint32, key *[8]uint32, flags uint32)")
	op("MOVD parents+0(FP), R0")
	op("MOVD cvs+8(FP), R1")
	op("MOVD key+16(FP), R2")
	op("MOVWU flags+24(FP), R4")
	loadRot8()
	comment("each pair of chaining values is one block")
	loadMessage8("R1", 64)
	broadcastKey8("R2")
	op("MOVD $64, R11")
	op("ORR $4, R4")
	init8(false, "R11", "R4")
	op("CALL rounds8<>(SB)")
	comment("finalize and store transposed chaining values")
	finalize8()
	storeCVs8()
	op("RET")
}

func genCompressBlocks8() {
	text("compressBlocks8NEON", 40, "(out *[512]byte, block *[16]uint32, cv *[8]uint32, counter uint64, blockLen uint32, flags uint32)")
	op("MOVD out+0(FP), R0")
	op("MOVD block+8(FP), R1")
	op("MOVD cv+16(FP), R2")
	op("MOVD counter+24(FP), R3")
	op("MOVWU blockLen+32(FP), R4")
	op("MOVWU flags+36(FP), R5")
	loadRot8()
	storeCounters8("R3")
	comment("every lane has the same message")
	for i := range 16 {
		op("MOVWU %d(R1), R9", 4*i)
		broadcast("R9", 24)
		op("FMOVQ F24, %s", msg8(0, i))
		op("FMOVQ F24, %s", msg8(1, i))
	}
	broadcastKey8("R2")
	init8(true, "R4", "R5")
	op("CALL rounds8<>(SB)")

	comment("finalize and store transposed outputs")
	for i := range 4 {
		op("MOVWU %d(R2), R9", 4*i)
		broadcast("R9", 29)
		op("MOVWU %d(R2), R9", 4*(4+i))
		broadcast("R9", 30)
		for s := range 2 {
			op("FMOVQ %s, F28", c8(s, i))
			op("VEOR V28.B16, V%d.B16, V%d.B16", reg8(s, i), reg8(s, i))
			op("VEOR V29.B16, V28.B16, V28.B16")
			op("FMOVQ F28, %s", c8(s, i))
			op("VEOR V%d.B16, V%d.B16, V%d.B16", reg8(s, 12+i), reg8(s, 4+i), reg8(s, 4+i))
			op("VEOR V30.B16, V%d.B16, V%d.B16", reg8(s, 12+i), reg8(s, 12+i))
		}
	}
	for s := range 2 {
		storeRows8(reg8(s, 0), "R0", 256*s, 64)
		storeRows8(reg8(s, 4), "R0", 256*s+16, 64)
		for i := range 4 {
			op("FMOVQ %s, F%d", c8(s, i), reg8(s, i))
		}
		storeRows8(reg8(s, 0), "R0", 256*s+32, 64)
		storeRows8(reg8(s, 12), "R0", 256*s+48, 64)
	}
	op("RET")
}

func main() {
	out := flag.String("out", "", "output file")
	flag.Parse()
	prelude()
	genCompressChunks()
	genCompressParents()
	genRounds()
	genCompressChunks8()
	genCompressParents8()
	genCompressBlocks8()
	genRounds8()
	genCompressNodeScalar()
	genCompressChunkBlocksScalar()
	genScalarRounds()
	if *out == "" {
		os.Stdout.Write(buf.Bytes())
	} else if err := os.WriteFile(*out, buf.Bytes(), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
