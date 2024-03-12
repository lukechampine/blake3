package blake3

import (
	"bytes"
	"encoding/binary"
	"io"
	"math/bits"
)

func compressGroup(p []byte, counter uint64) node {
	var stack [16][8]uint32
	var sc uint64
	pushSubtree := func(cv [8]uint32) {
		i := 0
		for sc&(1<<i) != 0 {
			cv = chainingValue(parentNode(stack[i], cv, iv, 0))
			i++
		}
		stack[i] = cv
		sc++
	}

	var buf [maxSIMD * chunkSize]byte
	var buflen int
	for len(p) > 0 {
		if buflen == len(buf) {
			pushSubtree(chainingValue(compressBuffer(&buf, buflen, &iv, counter+(sc*maxSIMD), 0)))
			buflen = 0
		}
		n := copy(buf[buflen:], p)
		buflen += n
		p = p[n:]
	}
	n := compressBuffer(&buf, buflen, &iv, counter+sc, 0)
	for i := bits.TrailingZeros64(sc); i < bits.Len64(sc); i++ {
		if sc&(1<<i) != 0 {
			n = parentNode(stack[i], chainingValue(n), iv, 0)
		}
	}
	return n
}

// BaoEncodedSize returns the size of a Bao encoding for the provided quantity
// of data.
func BaoEncodedSize(dataLen int, group int, outboard bool) int {
	groupSize := chunkSize << group
	size := 8
	if dataLen > 0 {
		chunks := (dataLen + groupSize - 1) / groupSize
		cvs := 2*chunks - 2 // no I will not elaborate
		size += cvs * 32
	}
	if !outboard {
		size += dataLen
	}
	return size
}

// BaoEncode computes the intermediate BLAKE3 tree hashes of data and writes
// them to dst. If outboard is false, the contents of data are also written to
// dst, interleaved with the tree hashes. It also returns the tree root, i.e.
// the 256-bit BLAKE3 hash. The group parameter controls how many chunks are
// hashed per "group," as a power of 2; for standard Bao, use 0.
//
// Note that dst is not written sequentially, and therefore must be initialized
// with sufficient capacity to hold the encoding; see BaoEncodedSize.
func BaoEncode(dst io.WriterAt, data io.Reader, dataLen int64, group int, outboard bool) ([32]byte, error) {
	groupSize := uint64(chunkSize << group)
	buf := make([]byte, groupSize)
	var err error
	read := func(p []byte) []byte {
		if err == nil {
			_, err = io.ReadFull(data, p)
		}
		return p
	}
	write := func(p []byte, off uint64) {
		if err == nil {
			_, err = dst.WriteAt(p, int64(off))
		}
	}
	var counter uint64

	// NOTE: unlike the reference implementation, we write directly in
	// pre-order, rather than writing in post-order and then flipping. This cuts
	// the I/O required in half, at the cost of making it a lot trickier to hash
	// multiple groups in SIMD. However, you can still get the SIMD speedup if
	// group > 0, so maybe just do that.
	var rec func(bufLen uint64, flags uint32, off uint64) (uint64, [8]uint32)
	rec = func(bufLen uint64, flags uint32, off uint64) (uint64, [8]uint32) {
		if err != nil {
			return 0, [8]uint32{}
		} else if bufLen <= groupSize {
			g := read(buf[:bufLen])
			if !outboard {
				write(g, off)
			}
			n := compressGroup(g, counter)
			counter += bufLen / chunkSize
			n.flags |= flags
			return 0, chainingValue(n)
		}
		mid := uint64(1) << (bits.Len64(bufLen-1) - 1)
		lchildren, l := rec(mid, 0, off+64)
		llen := lchildren * 32
		if !outboard {
			llen += (mid / groupSize) * groupSize
		}
		rchildren, r := rec(bufLen-mid, 0, off+64+llen)
		write(cvToBytes(&l)[:], off)
		write(cvToBytes(&r)[:], off+32)
		return 2 + lchildren + rchildren, chainingValue(parentNode(l, r, iv, flags))
	}

	binary.LittleEndian.PutUint64(buf[:8], uint64(dataLen))
	write(buf[:8], 0)
	_, root := rec(uint64(dataLen), flagRoot, 8)
	return *cvToBytes(&root), err
}

// BaoDecode reads content and tree data from the provided reader(s), and
// streams the verified content to dst. It returns false if verification fails.
// If the content and tree data are interleaved, outboard should be nil.
func BaoDecode(dst io.Writer, data, outboard io.Reader, group int, root [32]byte) (bool, error) {
	if outboard == nil {
		outboard = data
	}
	groupSize := uint64(chunkSize << group)
	buf := make([]byte, groupSize)
	var err error
	read := func(r io.Reader, p []byte) []byte {
		if err == nil {
			_, err = io.ReadFull(r, p)
		}
		return p
	}
	write := func(w io.Writer, p []byte) {
		if err == nil {
			_, err = w.Write(p)
		}
	}
	readParent := func() (l, r [8]uint32) {
		read(outboard, buf[:64])
		return bytesToCV(buf[:32]), bytesToCV(buf[32:])
	}
	var counter uint64
	var rec func(cv [8]uint32, bufLen uint64, flags uint32) bool
	rec = func(cv [8]uint32, bufLen uint64, flags uint32) bool {
		if err != nil {
			return false
		} else if bufLen <= groupSize {
			n := compressGroup(read(data, buf[:bufLen]), counter)
			counter += bufLen / chunkSize
			n.flags |= flags
			valid := cv == chainingValue(n)
			if valid {
				write(dst, buf[:bufLen])
			}
			return valid
		}
		l, r := readParent()
		n := parentNode(l, r, iv, flags)
		mid := uint64(1) << (bits.Len64(bufLen-1) - 1)
		return chainingValue(n) == cv && rec(l, mid, 0) && rec(r, bufLen-mid, 0)
	}

	read(outboard, buf[:8])
	dataLen := binary.LittleEndian.Uint64(buf[:8])
	ok := rec(bytesToCV(root[:]), dataLen, flagRoot)
	return ok, err
}

type bufferAt struct {
	buf []byte
}

func (b *bufferAt) WriteAt(p []byte, off int64) (int, error) {
	if copy(b.buf[off:], p) != len(p) {
		panic("bad buffer size")
	}
	return len(p), nil
}

// BaoEncodeBuf returns the Bao encoding and root (i.e. BLAKE3 hash) for data.
func BaoEncodeBuf(data []byte, group int, outboard bool) ([]byte, [32]byte) {
	buf := bufferAt{buf: make([]byte, BaoEncodedSize(len(data), group, outboard))}
	root, _ := BaoEncode(&buf, bytes.NewReader(data), int64(len(data)), group, outboard)
	return buf.buf, root
}

// BaoVerifyBuf verifies the Bao encoding and root (i.e. BLAKE3 hash) for data.
// If the content and tree data are interleaved, outboard should be nil.
func BaoVerifyBuf(data, outboard []byte, group int, root [32]byte) bool {
	d, o := bytes.NewBuffer(data), bytes.NewBuffer(outboard)
	var or io.Reader = o
	if outboard == nil {
		or = nil
	}
	ok, _ := BaoDecode(io.Discard, d, or, group, root)
	return ok && d.Len() == 0 && o.Len() == 0 // check for trailing data
}

// BaoExtractSlice returns the slice encoding for the given offset and length.
// When extracting from an outboard encoding, data should contain only the chunk
// groups that will be present in the slice.
func BaoExtractSlice(dst io.Writer, data, outboard io.Reader, group int, offset uint64, length uint64) error {
	combinedEncoding := outboard == nil
	if combinedEncoding {
		outboard = data
	}
	groupSize := uint64(chunkSize << group)
	buf := make([]byte, groupSize)
	var err error
	read := func(r io.Reader, n uint64, copy bool) {
		if err == nil {
			_, err = io.ReadFull(r, buf[:n])
			if err == nil && copy {
				_, err = dst.Write(buf[:n])
			}
		}
	}
	var pos uint64
	var rec func(bufLen uint64)
	rec = func(bufLen uint64) {
		inSlice := pos < (offset+length) && offset < (pos+bufLen)
		if err != nil {
			return
		} else if bufLen <= groupSize {
			if combinedEncoding || inSlice {
				read(data, bufLen, inSlice)
			}
			pos += bufLen
			return
		}
		read(outboard, 64, inSlice)
		mid := uint64(1) << (bits.Len64(bufLen-1) - 1)
		rec(mid)
		rec(bufLen - mid)
	}
	read(outboard, 8, true)
	rec(binary.LittleEndian.Uint64(buf[:8]))
	return err
}

// BaoDecodeSlice reads from data, which must contain a slice encoding for the
// given offset and length, and streams verified content to dst. It returns
// false if verification fails.
func BaoDecodeSlice(dst io.Writer, data io.Reader, group int, offset, length uint64, root [32]byte) (bool, error) {
	groupSize := uint64(chunkSize << group)
	buf := make([]byte, groupSize)
	var err error
	read := func(n uint64) []byte {
		if err == nil {
			_, err = io.ReadFull(data, buf[:n])
		}
		return buf[:n]
	}
	readParent := func() (l, r [8]uint32) {
		read(64)
		return bytesToCV(buf[:32]), bytesToCV(buf[32:])
	}
	write := func(p []byte) {
		if err == nil {
			_, err = dst.Write(p)
		}
	}
	var pos uint64
	var rec func(cv [8]uint32, bufLen uint64, flags uint32) bool
	rec = func(cv [8]uint32, bufLen uint64, flags uint32) bool {
		inSlice := pos < (offset+length) && offset < (pos+bufLen)
		if err != nil {
			return false
		} else if bufLen <= groupSize {
			if !inSlice {
				pos += bufLen
				return true
			}
			n := compressGroup(read(bufLen), pos/chunkSize)
			n.flags |= flags
			valid := cv == chainingValue(n)
			if valid {
				// only write within range
				p := buf[:bufLen]
				if pos+bufLen > offset+length {
					p = p[:offset+length-pos]
				}
				if pos < offset {
					p = p[offset-pos:]
				}
				write(p)
			}
			pos += bufLen
			return valid
		}
		if !inSlice {
			return true
		}
		l, r := readParent()
		n := parentNode(l, r, iv, flags)
		mid := uint64(1) << (bits.Len64(bufLen-1) - 1)
		return chainingValue(n) == cv && rec(l, mid, 0) && rec(r, bufLen-mid, 0)
	}

	dataLen := binary.LittleEndian.Uint64(read(8))
	ok := rec(bytesToCV(root[:]), dataLen, flagRoot)
	return ok, err
}

// BaoVerifySlice verifies the Bao slice encoding in data, returning the
// verified bytes.
func BaoVerifySlice(data []byte, group int, offset uint64, length uint64, root [32]byte) ([]byte, bool) {
	d := bytes.NewBuffer(data)
	var buf bytes.Buffer
	if ok, _ := BaoDecodeSlice(&buf, d, group, offset, length, root); !ok || d.Len() > 0 {
		return nil, false
	}
	return buf.Bytes(), true
}
