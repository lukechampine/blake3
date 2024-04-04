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
	for i := range vs {
		vs[i] = YMM()
		mv[i] = AllocLocal(32)
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

	performRoundsAVX2(vs, mv)

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
	for i := range vs {
		vs[i] = YMM()
		mv[i] = AllocLocal(32)
	}

	Comment("Load key")
	for i := 0; i < 8; i++ {
		VPBROADCASTD(key.Offset(i*4), vs[i])
	}

	Comment("Initialize counter")
	counterLo := AllocLocal(32)
	counterHi := AllocLocal(32)
	loadCounter(counter.Addr, vs[12:14], vs[14:16])
	VMOVDQU(vs[12], counterLo)
	VMOVDQU(vs[13], counterHi)

	Comment("Initialize flags")
	chunkFlags := AllocLocal(16 * 4)
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
	VMOVDQU(globals.seq, vs[9])
	VPSLLD(Imm(10), vs[9], vs[9]) // stride of 1024
	for i := 0; i < 16; i++ {
		VPCMPEQD(vs[8], vs[8], vs[8]) // fastest way to set all bits to 1
		VPGATHERDD(vs[8], buf.Offset(i*4).Idx(vs[9], 1), vs[10])
		VMOVDQU(vs[10], mv[i])
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

	performRoundsAVX2(vs, mv)

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
	for i := range vs {
		vs[i] = YMM()
		mv[i] = AllocLocal(32)
	}

	Comment("Load transposed block")
	VMOVDQU(globals.seq, vs[9])
	VPSLLD(Imm(6), vs[9], vs[9]) // stride of 64
	for i := 0; i < 16; i++ {
		VPCMPEQD(vs[8], vs[8], vs[8]) // fastest way to set all bits to 1
		VPGATHERDD(vs[8], cvs.Offset(i*4).Idx(vs[9], 1), vs[10])
		VMOVDQU(vs[10], mv[i])
	}

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

	performRoundsAVX2(vs, mv)

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

func performRoundsAVX2(sv [16]VecVirtual, mv [16]Mem) {
	spillMem := AllocLocal(32)
	tmp := sv[8]
	g := func(a, b, c, d VecVirtual, mx, my Mem) {
		// Helper function for performing rotations. Also manages c, tmp and
		// spillMem: if c == tmp, we need to spill and reload c using spillMem.
		rotr := func(v VecVirtual, n uint64, dst VecVirtual) {
			switch n {
			case 8, 16:
				shuf := [...]Mem{8: globals.shuffleRot8, 16: globals.shuffleRot16}[n]
				VPSHUFB(shuf, v, dst)
				if c == tmp {
					VMOVDQU(spillMem, c)
				}
			case 7, 12:
				if c == tmp {
					VMOVDQU(c, spillMem)
				}
				VPSRLD(Imm(n), v, tmp)
				VPSLLD(Imm(32-n), v, dst)
				VPOR(dst, tmp, dst)
			}
		}

		VPADDD(a, b, a)
		VPADDD(mx, a, a)
		VPXOR(d, a, d)
		rotr(d, 16, d)
		VPADDD(c, d, c)
		VPXOR(b, c, b)
		rotr(b, 12, b)
		VPADDD(a, b, a)
		VPADDD(my, a, a)
		VPXOR(d, a, d)
		rotr(d, 8, d)
		VPADDD(c, d, c)
		VPXOR(b, c, b)
		rotr(b, 7, b)
	}

	VMOVDQU(sv[8], spillMem) // spill
	for i := 0; i < 7; i++ {
		Comment(fmt.Sprintf("Round %v", i+1))
		g(sv[0], sv[4], sv[8], sv[12], mv[0], mv[1])
		g(sv[1], sv[5], sv[9], sv[13], mv[2], mv[3])
		g(sv[2], sv[6], sv[10], sv[14], mv[4], mv[5])
		g(sv[3], sv[7], sv[11], sv[15], mv[6], mv[7])
		g(sv[0], sv[5], sv[10], sv[15], mv[8], mv[9])
		g(sv[1], sv[6], sv[11], sv[12], mv[10], mv[11])
		g(sv[2], sv[7], sv[8], sv[13], mv[12], mv[13])
		g(sv[3], sv[4], sv[9], sv[14], mv[14], mv[15])

		// permute
		mv = [16]Mem{
			mv[2], mv[6], mv[3], mv[10],
			mv[7], mv[0], mv[4], mv[13],
			mv[1], mv[11], mv[12], mv[5],
			mv[9], mv[14], mv[15], mv[8],
		}
	}
	VMOVDQU(spillMem, sv[8]) // reload
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
