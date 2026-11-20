//go:build ignore
// +build ignore

package main

import (
	"fmt"

	. "github.com/mmcloughlin/avo/build"
	. "github.com/mmcloughlin/avo/operand"
	. "github.com/mmcloughlin/avo/reg"
)

func main() {
	genGlobals()
	genCompressBlocksAVX512()
	genCompressChunksAVX512()
	genCompressBlocksAVX2()
	genCompressChunksAVX2()
	genCompressParentsAVX2()
	genCompressNodeSSE41()
	genCompressChunkPairAVX2()

	Generate()
}

var globals struct {
	iv           Mem
	seq          Mem
	seq64        Mem // for loadCounter
	shuffleRot8  Mem
	shuffleRot16 Mem
}

func genGlobals() {
	globals.iv = GLOBL("iv", RODATA|NOPTR)
	DATA(0*4, U32(0x6A09E667))
	DATA(1*4, U32(0xBB67AE85))
	DATA(2*4, U32(0x3C6EF372))
	DATA(3*4, U32(0xA54FF53A))

	globals.seq = GLOBL("seq", RODATA|NOPTR)
	for i := 0; i < 16; i++ {
		DATA(i*4, U32(i))
	}
	globals.seq64 = GLOBL("seq64", RODATA|NOPTR)
	for i := 0; i < 8; i++ {
		DATA(i*8, U64(i))
	}
	globals.shuffleRot8 = GLOBL("shuffle_rot8", RODATA|NOPTR)
	for i := 0; i < 8; i++ {
		DATA(i*4, U32(0x00030201+0x04040404*i))
	}
	globals.shuffleRot16 = GLOBL("shuffle_rot16", RODATA|NOPTR)
	for i := 0; i < 8; i++ {
		DATA(i*4, U32(0x01000302+0x04040404*i))
	}
}

func genCompressBlocksAVX512() {
	TEXT("compressBlocksAVX512", NOSPLIT, "func(out *[1024]byte, block *[16]uint32, cv *[8]uint32, counter uint64, blockLen uint32, flags uint32)")
	out := Mem{Base: Load(Param("out"), GP64())}
	block := Mem{Base: Load(Param("block"), GP64())}
	cv := Mem{Base: Load(Param("cv"), GP64())}
	counter, _ := Param("counter").Resolve()
	blockLen, _ := Param("blockLen").Resolve()
	flags, _ := Param("flags").Resolve()

	Comment("Initialize block vectors")
	var vs, mv [16]VecVirtual
	for i := range vs {
		vs[i], mv[i] = ZMM(), ZMM()
		VPBROADCASTD(block.Offset(i*4), mv[i])
	}

	Comment("Initialize state vectors")
	for i, v := range vs {
		switch i {
		case 0, 1, 2, 3, 4, 5, 6, 7: // cv
			VPBROADCASTD(cv.Offset(i*4), v)
		case 8, 9, 10, 11: // iv
			VPBROADCASTD(globals.iv.Offset((i-8)*4), v)
		case 12: // counter
			VPBROADCASTD(counter.Addr, vs[12])
			VPADDD(globals.seq, vs[12], vs[12])
			// set a 1 bit in K1 for each overflowed counter in vs[12]
			VPCMPUD(Imm(1), globals.seq, vs[12], K1)
			// add 1 to each counter in vs[13] for each 1 bit in K1
			VPBROADCASTD(counter.Addr.Offset(1*4), vs[13])
			VPADDD_BCST(globals.seq.Offset(4), vs[13], K1, vs[13])
		case 14: // blockLen
			VPBROADCASTD(blockLen.Addr, v)
		case 15: // flags
			VPBROADCASTD(flags.Addr, v)
		}
	}

	performRoundsAVX512(vs, mv)

	Comment("Finalize CVs")
	for i, v := range vs[:8] {
		VPXORD(v, vs[i+8], v)
	}
	for i, v := range vs[8:] {
		VPXORD_BCST(cv.Offset(i*4), v, v)
	}
	stride := ZMM()
	VMOVDQU32(globals.seq, stride)
	VPSLLD(Imm(6), stride, stride) // stride of 64
	for i, v := range vs {
		KXNORD(K1, K1, K1) // fastest way to set all bits to 1
		VPSCATTERDD(v, K1, out.Offset(i*4).Idx(stride, 1))
	}

	RET()
}

func genCompressChunksAVX512() {
	TEXT("compressChunksAVX512", NOSPLIT, "func(cvs *[16][8]uint32, buf *[16384]byte, key *[8]uint32, counter uint64, flags uint32)")
	cvs := Mem{Base: Load(Param("cvs"), GP64())}
	buf := Mem{Base: Load(Param("buf"), GP64())}
	key := Mem{Base: Load(Param("key"), GP64())}
	counter, _ := Param("counter").Resolve()
	flags, _ := Param("flags").Resolve()

	var vs, mv [16]VecVirtual
	for i := range vs {
		vs[i], mv[i] = ZMM(), ZMM()
	}

	Comment("Initialize counter")
	counterLo := AllocLocal(64)
	counterHi := AllocLocal(64)
	VPBROADCASTD(counter.Addr, vs[0])
	VPADDD(globals.seq, vs[0], vs[0])
	VPCMPUD(Imm(1), globals.seq, vs[0], K1)
	VPBROADCASTD(counter.Addr.Offset(4), vs[1])
	VPADDD_BCST(globals.seq.Offset(4), vs[1], K1, vs[1])
	VMOVDQU32(vs[0], counterLo)
	VMOVDQU32(vs[1], counterHi)

	Comment("Initialize flags")
	chunkFlags := AllocLocal(16 * 4)
	VPBROADCASTD(flags.Addr, vs[0])
	VMOVDQU32(vs[0], chunkFlags)
	ORL(Imm(1), chunkFlags.Offset(0*4))
	ORL(Imm(2), chunkFlags.Offset(15*4))

	Comment("Load key")
	for i := 0; i < 8; i++ {
		VPBROADCASTD(key.Offset(i*4), vs[i])
	}

	Comment("Loop index")
	loop := GP64()
	XORQ(loop, loop)
	Label("loop")

	Comment("Load transposed block")
	VMOVDQU32(globals.seq, vs[8])
	VPSLLD(Imm(10), vs[8], vs[8]) // stride of 1024
	for i, m := range mv {
		KXNORD(K1, K1, K1)
		VPGATHERDD(buf.Offset(i*4).Idx(vs[8], 1), K1, m)
	}
	ADDQ(Imm(64), buf.Base)

	Comment("Reload state vectors (other than CVs)")
	for i := 0; i < 4; i++ {
		VPBROADCASTD(globals.iv.Offset(i*4), vs[8+i])
	}
	VMOVDQU32(counterLo, vs[12])
	VMOVDQU32(counterHi, vs[13])
	VPBROADCASTD(globals.seq.Offset(4), vs[14])
	VPSLLD(Imm(6), vs[14], vs[14]) // 64
	VPBROADCASTD(chunkFlags.Idx(loop, 4), vs[15])

	performRoundsAVX512(vs, mv)

	Comment("Finalize CVs")
	for i := range vs[:8] {
		VPXORD(vs[i], vs[i+8], vs[i])
	}

	Comment("Loop")
	INCQ(loop)
	CMPQ(loop, U32(16))
	JNE(LabelRef("loop"))

	Comment("Finished; transpose CVs")
	VMOVDQU32(globals.seq, vs[8])
	VPSLLD(Imm(5), vs[8], vs[8]) // stride of 32
	for i, v := range vs[:8] {
		KXNORD(K1, K1, K1) // fastest way to set all bits to 1
		VPSCATTERDD(v, K1, cvs.Offset(i*4).Idx(vs[8], 1))
	}

	RET()
}

func performRoundsAVX512(vs, mv [16]VecVirtual) {
	g := func(a, b, c, d, mx, my VecVirtual) {
		VPADDD(a, b, a)
		VPADDD(mx, a, a)
		VPXORD(d, a, d)
		VPRORD(Imm(16), d, d)
		VPADDD(c, d, c)
		VPXORD(b, c, b)
		VPRORD(Imm(12), b, b)
		VPADDD(a, b, a)
		VPADDD(my, a, a)
		VPXORD(d, a, d)
		VPRORD(Imm(8), d, d)
		VPADDD(c, d, c)
		VPXORD(b, c, b)
		VPRORD(Imm(7), b, b)
	}

	for i := 0; i < 7; i++ {
		Comment(fmt.Sprintf("Round %v", i+1))
		g(vs[0], vs[4], vs[8], vs[12], mv[0], mv[1])
		g(vs[1], vs[5], vs[9], vs[13], mv[2], mv[3])
		g(vs[2], vs[6], vs[10], vs[14], mv[4], mv[5])
		g(vs[3], vs[7], vs[11], vs[15], mv[6], mv[7])
		g(vs[0], vs[5], vs[10], vs[15], mv[8], mv[9])
		g(vs[1], vs[6], vs[11], vs[12], mv[10], mv[11])
		g(vs[2], vs[7], vs[8], vs[13], mv[12], mv[13])
		g(vs[3], vs[4], vs[9], vs[14], mv[14], mv[15])

		// permute
		mv = [16]VecVirtual{
			mv[2], mv[6], mv[3], mv[10],
			mv[7], mv[0], mv[4], mv[13],
			mv[1], mv[11], mv[12], mv[5],
			mv[9], mv[14], mv[15], mv[8],
		}
	}
}

func genCompressBlocksAVX2() {
	TEXT("compressBlocksAVX2", NOSPLIT, "func(out *[512]byte, block *[16]uint32, cv *[8]uint32, counter uint64, blockLen uint32, flags uint32)")
	out := Mem{Base: Load(Param("out"), GP64())}
	block := Mem{Base: Load(Param("block"), GP64())}
	cv := Mem{Base: Load(Param("cv"), GP64())}
	counter, _ := Param("counter").Resolve()
	blockLen, _ := Param("blockLen").Resolve()
	flags, _ := Param("flags").Resolve()

	var vs [16]VecVirtual
	var mv [16]Mem
	locals := alignedLocals(17)
	for i := range vs {
		vs[i] = YMM()
		mv[i] = locals[i]
	}

	Comment("Load block")
	for i := 0; i < 16; i++ {
		VPBROADCASTD(block.Offset(i*4), vs[0])
		VMOVDQU(vs[0], mv[i])
	}

	Comment("Initialize state vectors")
	for i, v := range vs {
		switch i {
		case 0, 1, 2, 3, 4, 5, 6, 7: // cv
			VPBROADCASTD(cv.Offset(i*4), v)
		case 8, 9, 10, 11: // iv
			VPBROADCASTD(globals.iv.Offset((i-8)*4), v)
		case 12: // counter
			loadCounter(counter.Addr, vs[12:14], vs[14:16])
		case 14: // blockLen
			VPBROADCASTD(blockLen.Addr, v)
		case 15: // flags
			VPBROADCASTD(flags.Addr, v)
		}
	}

	performRoundsAVX2(vs, mv, locals[16])

	Comment("Finalize CVs")
	for i := 8; i < 16; i++ {
		VMOVDQU(vs[i], mv[i])
	}
	for i := range vs[:8] {
		VPXOR(vs[i], vs[i+8], vs[i])
	}
	transpose(vs[:8], vs[8:])
	for i, v := range vs[8:] {
		VMOVDQU(v, out.Offset(i*64))
	}
	for i := 8; i < 16; i++ {
		VMOVDQU(mv[i], vs[i])
	}
	for i, v := range vs[8:] {
		VPBROADCASTD(cv.Offset(i*4), vs[0])
		VPXOR(vs[0], v, v)
	}
	transpose(vs[8:], vs[:8])
	for i, v := range vs[:8] {
		VMOVDQU(v, out.Offset(i*64+32))
	}

	// See https://community.intel.com/t5/Intel-ISA-Extensions/What-is-the-status-of-VZEROUPPER-use/m-p/1098375
	VZEROUPPER()
	RET()
}

func genCompressChunksAVX2() {
	TEXT("compressChunksAVX2", NOSPLIT, "func(cvs *[8][8]uint32, buf *[8192]byte, key *[8]uint32, counter uint64, flags uint32)")
	cvs := Mem{Base: Load(Param("cvs"), GP64())}
	buf := Mem{Base: Load(Param("buf"), GP64())}
	key := Mem{Base: Load(Param("key"), GP64())}
	counter, _ := Param("counter").Resolve()
	flags, _ := Param("flags").Resolve()

	var vs [16]VecVirtual
	var mv [16]Mem
	locals := alignedLocals(21)
	for i := range vs {
		vs[i] = YMM()
		mv[i] = locals[i]
	}

	Comment("Load key")
	for i := 0; i < 8; i++ {
		VPBROADCASTD(key.Offset(i*4), vs[i])
	}

	Comment("Initialize counter")
	counterLo := locals[17]
	counterHi := locals[18]
	loadCounter(counter.Addr, vs[12:14], vs[14:16])
	VMOVDQU(vs[12], counterLo)
	VMOVDQU(vs[13], counterHi)

	Comment("Initialize flags")
	chunkFlags := locals[19] // and locals[20]
	VPBROADCASTD(flags.Addr, vs[14])
	VMOVDQU(vs[14], chunkFlags.Offset(0*32))
	VMOVDQU(vs[14], chunkFlags.Offset(1*32))
	ORL(Imm(1), chunkFlags.Offset(0*4))
	ORL(Imm(2), chunkFlags.Offset(15*4))

	Comment("Loop index")
	loop := GP64()
	XORQ(loop, loop)
	Label("loop")

	Comment("Load transposed block")
	loadTransposed(buf, 1024, vs[8:], mv)
	for j := 0; j < 8; j++ {
		PREFETCHT0(buf.Offset(j*1024 + 192))
	}
	ADDQ(Imm(64), buf.Base)

	Comment("Reload state vectors (other than CVs)")
	for i := 0; i < 4; i++ {
		VPBROADCASTD(globals.iv.Offset(i*4), vs[8+i])
	}
	VMOVDQU(counterLo, vs[12])
	VMOVDQU(counterHi, vs[13])
	VPBROADCASTD(globals.seq.Offset(4), vs[14])
	VPSLLD(Imm(6), vs[14], vs[14]) // 64
	VPBROADCASTD(chunkFlags.Idx(loop, 4), vs[15])

	performRoundsAVX2(vs, mv, locals[16])

	Comment("Finalize CVs")
	for i := range vs[:8] {
		VPXOR(vs[i], vs[i+8], vs[i])
	}

	Comment("Loop")
	INCQ(loop)
	CMPQ(loop, U32(16))
	JNE(LabelRef("loop"))

	Comment("Finished; transpose CVs")
	transpose(vs[:8], vs[8:])
	for i, v := range vs[8:] {
		VMOVDQU(v, cvs.Offset(i*32))
	}

	VZEROUPPER()
	RET()
}

func genCompressParentsAVX2() {
	TEXT("compressParentsAVX2", NOSPLIT, "func(parents *[8][8]uint32, cvs *[16][8]uint32, key *[8]uint32, flags uint32)")
	parents := Mem{Base: Load(Param("parents"), GP64())}
	cvs := Mem{Base: Load(Param("cvs"), GP64())}
	key := Mem{Base: Load(Param("key"), GP64())}
	flags, _ := Param("flags").Resolve()

	var vs [16]VecVirtual
	var mv [16]Mem
	locals := alignedLocals(17)
	for i := range vs {
		vs[i] = YMM()
		mv[i] = locals[i]
	}

	Comment("Load transposed block")
	loadTransposed(cvs, 64, vs[8:], mv)

	Comment("Initialize state vectors")
	for i, v := range vs {
		switch i {
		case 0, 1, 2, 3, 4, 5, 6, 7: // cv
			VPBROADCASTD(key.Offset(i*4), v)
		case 8, 9, 10, 11: // iv
			VPBROADCASTD(globals.iv.Offset((i-8)*4), v)
		case 12, 13: // counter
			VPXOR(v, v, v)
		case 14: // blockLen
			VPBROADCASTD(globals.seq.Offset(1*4), v)
			VPSLLD(Imm(6), v, v) // 64
		case 15: // flags
			ORL(Imm(4), flags.Addr) // flagParent
			VPBROADCASTD(flags.Addr, v)
		}
	}

	performRoundsAVX2(vs, mv, locals[16])

	Comment("Finalize CVs")
	for i := range vs[:8] {
		VPXOR(vs[i], vs[i+8], vs[i])
	}
	transpose(vs[:8], vs[8:])
	for i, v := range vs[8:] {
		VMOVDQU(v, parents.Offset(i*32))
	}

	VZEROUPPER()
	RET()
}

// alignedLocals allocates n 32-byte slots on the stack, aligned such that none
// of them straddles a cache line. Go only aligns the stack to 8 bytes, so
// without this, the speed of the AVX2 routines depends on their caller's stack
// layout.
func alignedLocals(n int) []Mem {
	base := GP64()
	LEAQ(AllocLocal(32*n+32), base)
	ADDQ(Imm(31), base)
	ANDQ(I8(-32), base)
	locals := make([]Mem, n)
	for i := range locals {
		locals[i] = Mem{Base: base, Disp: 32 * i}
	}
	return locals
}

func performRoundsAVX2(sv [16]VecVirtual, mv [16]Mem, spillMem Mem) {
	cols := [4][4]int{{0, 4, 8, 12}, {1, 5, 9, 13}, {2, 6, 10, 14}, {3, 7, 11, 15}}
	diags := [4][4]int{{0, 5, 10, 15}, {1, 6, 11, 12}, {2, 7, 8, 13}, {3, 4, 9, 14}}
	// half performs half of G on four independent sets of state vectors.
	// Each step is emitted for all four sets before moving on to the next,
	// so that the CPU can execute them in parallel.
	half := func(gs [4][4]int, m [4]Mem, shuf Mem, n uint64) {
		for i, g := range gs {
			// NOTE: the message is added before b, since b is the last of
			// the three to become available.
			VPADDD(m[i], sv[g[0]], sv[g[0]])
		}
		for _, g := range gs {
			VPADDD(sv[g[1]], sv[g[0]], sv[g[0]])
		}
		for _, g := range gs {
			VPXOR(sv[g[0]], sv[g[3]], sv[g[3]])
		}
		for _, g := range gs {
			VPSHUFB(shuf, sv[g[3]], sv[g[3]])
		}
		for _, g := range gs {
			VPADDD(sv[g[3]], sv[g[2]], sv[g[2]])
		}
		for _, g := range gs {
			VPXOR(sv[g[2]], sv[g[1]], sv[g[1]])
		}
		// the shifts need a temporary register, so spill one
		tmp := sv[8]
		VMOVDQU(tmp, spillMem)
		for _, g := range gs {
			b := sv[g[1]]
			VPSRLD(Imm(n), b, tmp)
			VPSLLD(Imm(32-n), b, b)
			VPOR(tmp, b, b)
		}
		VMOVDQU(spillMem, tmp)
	}

	for i := 0; i < 7; i++ {
		Comment(fmt.Sprintf("Round %v", i+1))
		half(cols, [4]Mem{mv[0], mv[2], mv[4], mv[6]}, globals.shuffleRot16, 12)
		half(cols, [4]Mem{mv[1], mv[3], mv[5], mv[7]}, globals.shuffleRot8, 7)
		half(diags, [4]Mem{mv[8], mv[10], mv[12], mv[14]}, globals.shuffleRot16, 12)
		half(diags, [4]Mem{mv[9], mv[11], mv[13], mv[15]}, globals.shuffleRot8, 7)

		// permute
		mv = [16]Mem{
			mv[2], mv[6], mv[3], mv[10],
			mv[7], mv[0], mv[4], mv[13],
			mv[1], mv[11], mv[12], mv[5],
			mv[9], mv[14], mv[15], mv[8],
		}
	}
}

func genCompressNodeSSE41() {
	TEXT("compressNodeSSE41", NOSPLIT, "func(out *[16]uint32, cv *[8]uint32, block *[16]uint32, counter uint64, blockLen uint32, flags uint32)")
	out := Mem{Base: Load(Param("out"), GP64())}
	cv := Mem{Base: Load(Param("cv"), GP64())}
	block := Mem{Base: Load(Param("block"), GP64())}
	counter, _ := Param("counter").Resolve()
	blockLen, _ := Param("blockLen").Resolve()
	flags, _ := Param("flags").Resolve()

	// Unlike the other routines, which compress many nodes at once, this one
	// compresses a single node, using one vector for each row of its state.
	// The approach, including the message shuffles, follows the official
	// SSE4.1 implementation.
	Comment("Initialize state vectors")
	a, b, c, d := XMM(), XMM(), XMM(), XMM()
	MOVOU(cv.Offset(0), a)
	MOVOU(cv.Offset(16), b)
	MOVOU(globals.iv, c)
	MOVQ(counter.Addr, d)
	PINSRD(Imm(2), blockLen.Addr, d)
	PINSRD(Imm(3), flags.Addr, d)

	Comment("Load block")
	var m, t [4]VecVirtual
	for i := range m {
		m[i], t[i] = XMM(), XMM()
		MOVOU(block.Offset(i*16), m[i])
	}

	rot8, rot16 := XMM(), XMM()
	MOVOU(globals.shuffleRot8, rot8)
	MOVOU(globals.shuffleRot16, rot16)

	// g performs half of the G function on all four columns.
	tmp := XMM()
	g := func(mv, shuf VecVirtual, n uint64) {
		PADDD(mv, a)
		PADDD(b, a)
		PXOR(a, d)
		PSHUFB(shuf, d)
		PADDD(d, c)
		PXOR(c, b)
		MOVO(b, tmp)
		PSRLL(Imm(n), b)
		PSLLL(Imm(32-n), tmp)
		POR(tmp, b)
	}
	// Rotating the rows turns the diagonals into columns. The second row is
	// the one left in place, since it is on the critical path; the message
	// vectors for the diagonals are arranged to match.
	diagonalize := func() {
		PSHUFD(Imm(0x93), a, a)
		PSHUFD(Imm(0x4E), d, d)
		PSHUFD(Imm(0x39), c, c)
	}
	undiagonalize := func() {
		PSHUFD(Imm(0x39), a, a)
		PSHUFD(Imm(0x4E), d, d)
		PSHUFD(Imm(0x93), c, c)
	}

	for i := 0; i < 7; i++ {
		Comment(fmt.Sprintf("Round %v", i+1))
		if i == 0 {
			// group the message words by the G calls that consume them
			MOVO(m[0], t[0])
			SHUFPS(Imm(0x88), m[1], t[0])
			g(t[0], rot16, 12)
			MOVO(m[0], t[1])
			SHUFPS(Imm(0xDD), m[1], t[1])
			g(t[1], rot8, 7)
			diagonalize()
			MOVO(m[2], t[2])
			SHUFPS(Imm(0x88), m[3], t[2])
			PSHUFD(Imm(0x93), t[2], t[2])
			g(t[2], rot16, 12)
			MOVO(m[2], t[3])
			SHUFPS(Imm(0xDD), m[3], t[3])
			PSHUFD(Imm(0x93), t[3], t[3])
			g(t[3], rot8, 7)
			undiagonalize()
		} else {
			// permute the message words from the previous round
			MOVO(m[0], t[0])
			SHUFPS(Imm(0xD6), m[1], t[0])
			PSHUFD(Imm(0x39), t[0], t[0])
			g(t[0], rot16, 12)
			MOVO(m[2], t[1])
			SHUFPS(Imm(0xFA), m[3], t[1])
			PSHUFD(Imm(0x0F), m[0], tmp)
			PBLENDW(Imm(0xCC), t[1], tmp)
			MOVO(tmp, t[1])
			g(t[1], rot8, 7)
			diagonalize()
			MOVO(m[3], t[2])
			PUNPCKLQDQ(m[1], t[2])
			PBLENDW(Imm(0xC0), m[2], t[2])
			PSHUFD(Imm(0x78), t[2], t[2])
			g(t[2], rot16, 12)
			MOVO(m[1], t[3])
			PUNPCKHLQ(m[3], t[3])
			MOVO(m[2], tmp)
			PUNPCKLLQ(t[3], tmp)
			PSHUFD(Imm(0x1E), tmp, t[3])
			g(t[3], rot8, 7)
			undiagonalize()
		}
		m, t = t, m
	}

	Comment("Finalize")
	PXOR(c, a)
	PXOR(d, b)
	MOVOU(cv.Offset(0), tmp)
	PXOR(tmp, c)
	MOVOU(cv.Offset(16), tmp)
	PXOR(tmp, d)
	MOVOU(a, out.Offset(0))
	MOVOU(b, out.Offset(16))
	MOVOU(c, out.Offset(32))
	MOVOU(d, out.Offset(48))
	RET()
}

func genCompressChunkPairAVX2() {
	TEXT("compressChunkPairAVX2", NOSPLIT, "func(cvs *[2][8]uint32, p0 *byte, p1 *byte, blocks uint64, key *[8]uint32, counter uint64, flags uint32, flagsEnd uint32)")
	cvs := Mem{Base: Load(Param("cvs"), GP64())}
	p0 := Mem{Base: Load(Param("p0"), GP64())}
	p1 := Mem{Base: Load(Param("p1"), GP64())}
	blocks := Load(Param("blocks"), GP64())
	key := Mem{Base: Load(Param("key"), GP64())}
	counter := Load(Param("counter"), GP64())
	flags := Load(Param("flags"), GP32())
	flagsEnd := Load(Param("flagsEnd"), GP32())

	// This routine compresses the leading blocks of two chunks at once. Like
	// compressNodeSSE41, it uses one vector for each row of the state, but
	// with one chunk in each half of the vector. This is faster than the
	// other AVX2 routines when there are only one or two chunks to compress.
	Comment("Initialize chaining values")
	a, b, c, d := YMM(), YMM(), YMM(), YMM()
	VBROADCASTI128(key.Offset(0), a)
	VBROADCASTI128(key.Offset(16), b)

	Comment("Initialize counters and block length")
	row3 := AllocLocal(32)
	MOVQ(counter, row3.Offset(0))
	MOVQ(U32(64), row3.Offset(8))
	INCQ(counter)
	MOVQ(counter, row3.Offset(16))
	MOVQ(U32(64), row3.Offset(24))

	Comment("The first block is the chunk start")
	blockFlags := GP32()
	MOVL(flags, blockFlags)
	ORL(Imm(1), blockFlags)

	var m, t [4]VecVirtual
	for i := range m {
		m[i], t[i] = YMM(), YMM()
	}
	tmp := YMM()

	// g performs half of the G function on all four columns of both chunks.
	g := func(mv VecVirtual, shuf Mem, n uint64) {
		VPADDD(mv, a, a)
		VPADDD(b, a, a)
		VPXOR(a, d, d)
		VPSHUFB(shuf, d, d)
		VPADDD(d, c, c)
		VPXOR(c, b, b)
		VPSRLD(Imm(n), b, tmp)
		VPSLLD(Imm(32-n), b, b)
		VPOR(tmp, b, b)
	}
	diagonalize := func() {
		VPSHUFD(Imm(0x93), a, a)
		VPSHUFD(Imm(0x4E), d, d)
		VPSHUFD(Imm(0x39), c, c)
	}
	undiagonalize := func() {
		VPSHUFD(Imm(0x39), a, a)
		VPSHUFD(Imm(0x4E), d, d)
		VPSHUFD(Imm(0x93), c, c)
	}

	Label("pairloop")
	Comment("The last block may have additional flags")
	lastFlags := GP32()
	MOVL(blockFlags, lastFlags)
	ORL(flagsEnd, lastFlags)
	CMPQ(blocks, Imm(1))
	CMOVLEQ(lastFlags, blockFlags)

	Comment("Initialize state vectors")
	VBROADCASTI128(globals.iv, c)
	VMOVD(blockFlags, tmp.AsX())
	VPBROADCASTD(tmp.AsX(), tmp)
	VPBLENDD(Imm(0x77), row3, tmp, d)

	Comment("Load block")
	for i := range m {
		VMOVDQU(p0.Offset(i*16), m[i].AsX())
		VINSERTI128(Imm(1), p1.Offset(i*16), m[i], m[i])
	}

	for i := 0; i < 7; i++ {
		Comment(fmt.Sprintf("Round %v", i+1))
		if i == 0 {
			VSHUFPS(Imm(0x88), m[1], m[0], t[0])
			g(t[0], globals.shuffleRot16, 12)
			VSHUFPS(Imm(0xDD), m[1], m[0], t[1])
			g(t[1], globals.shuffleRot8, 7)
			diagonalize()
			VSHUFPS(Imm(0x88), m[3], m[2], t[2])
			VPSHUFD(Imm(0x93), t[2], t[2])
			g(t[2], globals.shuffleRot16, 12)
			VSHUFPS(Imm(0xDD), m[3], m[2], t[3])
			VPSHUFD(Imm(0x93), t[3], t[3])
			g(t[3], globals.shuffleRot8, 7)
			undiagonalize()
		} else {
			VSHUFPS(Imm(0xD6), m[1], m[0], t[0])
			VPSHUFD(Imm(0x39), t[0], t[0])
			g(t[0], globals.shuffleRot16, 12)
			VSHUFPS(Imm(0xFA), m[3], m[2], t[1])
			VPSHUFD(Imm(0x0F), m[0], tmp)
			VPBLENDW(Imm(0xCC), t[1], tmp, t[1])
			g(t[1], globals.shuffleRot8, 7)
			diagonalize()
			VPUNPCKLQDQ(m[1], m[3], t[2])
			VPBLENDW(Imm(0xC0), m[2], t[2], t[2])
			VPSHUFD(Imm(0x78), t[2], t[2])
			g(t[2], globals.shuffleRot16, 12)
			VPUNPCKHDQ(m[3], m[1], t[3])
			VPUNPCKLDQ(t[3], m[2], tmp)
			VPSHUFD(Imm(0x1E), tmp, t[3])
			g(t[3], globals.shuffleRot8, 7)
			undiagonalize()
		}
		m, t = t, m
	}

	Comment("Finalize chaining values")
	VPXOR(c, a, a)
	VPXOR(d, b, b)

	Comment("Only the first block is the chunk start")
	MOVL(flags, blockFlags)
	ADDQ(Imm(64), p0.Base)
	ADDQ(Imm(64), p1.Base)
	DECQ(blocks)
	JNZ(LabelRef("pairloop"))

	Comment("Store chaining values")
	VMOVDQU(a.AsX(), cvs.Offset(0))
	VMOVDQU(b.AsX(), cvs.Offset(16))
	VEXTRACTI128(Imm(1), a, cvs.Offset(32))
	VEXTRACTI128(Imm(1), b, cvs.Offset(48))
	VZEROUPPER()
	RET()
}

func loadCounter(counter Mem, dst, scratch []VecVirtual) {
	// fill dst[0] and dst[1] with counter + 0,1,2,3,4,5,6,7, then transpose so
	// that dst[0] contains low 32 bits and dst[1] contains high 32 bits.
	VPBROADCASTQ(counter, dst[0])
	VPBROADCASTQ(counter, dst[1])
	VPADDQ(globals.seq64.Offset(0*4), dst[0], dst[0])
	VPADDQ(globals.seq64.Offset(8*4), dst[1], dst[1])
	VPUNPCKLDQ(dst[1], dst[0], scratch[0])
	VPUNPCKHDQ(dst[1], dst[0], scratch[1])
	VPUNPCKLDQ(scratch[1], scratch[0], dst[0])
	VPUNPCKHDQ(scratch[1], scratch[0], dst[1])
	const perm = 0<<0 | 2<<2 | 1<<4 | 3<<6
	VPERMQ(Imm(perm), dst[0], dst[0])
	VPERMQ(Imm(perm), dst[1], dst[1])
}

// loadTransposed loads a 64-byte block from each of 8 rows, stride bytes
// apart, and stores the transposed message in mv, using the 8 registers in vs
// as scratch space. The approach follows the official AVX2 implementation.
func loadTransposed(rows Mem, stride int, vs []VecVirtual, mv [16]Mem) {
	r, t := vs[:4], vs[4:8]
	for q := 0; q < 4; q++ {
		// each register holds four words from two rows, one in each half
		for j := 0; j < 4; j++ {
			VMOVDQU(rows.Offset(j*stride+q*16), r[j].AsX())
			VINSERTI128(Imm(1), rows.Offset((j+4)*stride+q*16), r[j], r[j])
		}
		VPUNPCKLQDQ(r[1], r[0], t[0])
		VPUNPCKHQDQ(r[1], r[0], t[1])
		VPUNPCKLQDQ(r[3], r[2], t[2])
		VPUNPCKHQDQ(r[3], r[2], t[3])
		VSHUFPS(Imm(0x88), t[2], t[0], r[0])
		VSHUFPS(Imm(0xDD), t[2], t[0], r[1])
		VSHUFPS(Imm(0x88), t[3], t[1], r[2])
		VSHUFPS(Imm(0xDD), t[3], t[1], r[3])
		for i := 0; i < 4; i++ {
			VMOVDQU(r[i], mv[q*4+i])
		}
	}
}

func transpose(src, dst []VecVirtual) {
	// interleave uint32s
	for i := 0; i < 8; i += 2 {
		VPUNPCKLDQ(src[i+1], src[i], dst[i+0])
		VPUNPCKHDQ(src[i+1], src[i], dst[i+1])
	}
	// interleave groups of two uint32s
	for i := 0; i < 4; i++ {
		j := i*2 - i%2 // j := 0,1,4,5
		VPUNPCKLQDQ(dst[j+2], dst[j], src[i*2+0])
		VPUNPCKHQDQ(dst[j+2], dst[j], src[i*2+1])
	}
	// interleave groups of four uint32s
	for i := 0; i < 4; i++ {
		VPERM2I128(Imm(0x20), src[i+4], src[i], dst[i+0])
		VPERM2I128(Imm(0x31), src[i+4], src[i], dst[i+4])
	}
}
