// Package blake3 implements the BLAKE3 cryptographic hash function.
package blake3 // import "lukechampine.com/blake3"

import (
	"encoding/binary"
	"fmt"
	"io"
	//"math/bits"
	"os"
	"runtime"
	"sync"

	"lukechampine.com/blake3/guts"
)

// job delegates file hashing duties
// out to multiple parallel goroutines
// that hash different segments of a
// single file. See HashFile and HashFile2
// below.
type job struct {
	beg  int64
	endx int64

	nodeK int

	isLast bool
}

// HashFile gives the unkeyed Blake3 512-bit hash of a file
// using multiple parallel goroutines to read and hash.
// See HashFile2 to control the details, or to set a key.
//
// We return a Hasher h that starts with our file
// already written into it, to allow other trailing
// meta data to be added to the hash if you wish.
//
// The returned 512-bit hash value in sum is ready for use; it is
// equal to h.Sum() before any other additions.
func HashFile(path string) (sum []byte, h *Hasher, err error) {
	sum, h, err = HashFile2(path, nil, 0, 0)
	return
}

// HashFile2 processes a file in parallel using
// segments of size (1 << parallelBits) bytes.
//
// parallelBits == 0 means use the default (19).
//
// parallelBits < 14 will be ignored and we'll use 14,
// as that gives the minimum segment size of
// MaxSIMD(16) * ChunkSize(1024).
//
// We use runtime.NumCPU goroutines to read and hash
// if ngoro <= 0; else we use ngoro.
//
// The simple call is HashFile2(path, nil, 0, 0) for
// the defaults. See HashFile for an easy invocation.
//
// We return a Hasher h that starts with our file
// already written into it, to allow other trailing
// meta data to be added to the hash if you wish.
//
// The returned 512-bit hash value is ready for use; it is
// equal to h.Sum() before any other additions.
//
// A note on what is not provided:
//
// Note that it isn't possible in general to
// hash a second file quickly (in parallel) into the
// returned hash due to alignment issues: Blake3
// is sensitive to the exact position of each
// byte in the stream. Thus it isn't possible
// to implement a method such as Hasher.HashFile() and
// have it be parallel. Hence such an
// API is not provided; HashFile returns a new
// Hasher but cannot do a parallel write a file into
// an existing, already written-to, Hasher.
//
// What to do instead? We recommend doing a
// fast, parallel HashFile or HashFile2 call
// per file, and then combining the output hashes with
// a separate top-level Hasher to
// enable maximum parallelism on each file.
func HashFile2(
	path string,
	key []byte,
	parallelBits int,
	ngoro int,
) (sum []byte, h *Hasher, err0 error) {

	// update and return at the end.
	h = New(64, key)

	var flags uint32
	var keyWords [8]uint32
	if key == nil {
		keyWords = guts.IV
	} else {
		for i := range keyWords {
			keyWords[i] = binary.LittleEndian.Uint32(key[i*4:])
		}
		flags |= guts.FlagKeyedHash
	}

	fd, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		err0 = err
		return
	}
	defer fd.Close()

	fi, err := fd.Stat()
	if err != nil {
		err0 = err
		return
	}
	sz := fi.Size()

	const per = guts.MaxSIMD * guts.ChunkSize // 16KB

	// segment is the size in bytes that one goroutine
	// reads from disk and hashes.
	segment := int64(1 << 19) // 512KB by default.
	if parallelBits != 0 {
		segment = 1 << parallelBits
	}
	if segment < per {
		segment = per
	}

	if sz <= segment {
		// too small to parallelize, just add it directly
		// and return
		buf := make([]byte, sz)
		_, err := io.ReadFull(fd, buf)
		if err != nil {
			return nil, nil, err
		}
		h.Write(buf)
		return h.Sum(nil), h, nil
	}
	// INVAR: sz > segment

	perSeg := uint64(segment / per) // number of 16KB buffers in one segment.
	_ = perSeg

	jobN := sz / segment
	if sz*segment < jobN {
		jobN++ // round up. any fraction left at the end still gets processed.
	}
	if jobN == 0 {
		panic("sz <= segment above should have prevented this.")
	}

	// how big a goroutine pool to use
	// to process the jobs.
	nCPU := runtime.NumCPU()
	nWorkers := int64(nCPU)
	if ngoro > 0 {
		nWorkers = int64(ngoro)
	}

	if jobN < nWorkers {
		nWorkers = jobN // get smaller, but not larger.
	}

	buf := make([][]byte, nWorkers)
	for i := int64(0); i < nWorkers; i++ {
		buf[i] = make([]byte, segment)
	}

	// buffered channel for less waiting on scheduling.
	work := make(chan *job, 2*nCPU)
	var wg sync.WaitGroup
	wg.Add(int(nWorkers))

	// the number of sub-tree root-nodes (only
	// marked as parents though) to be merged after
	// all the parallel hashing is done.
	nNodes := (sz + segment - 1) / segment
	cvs := make([][8]uint32, nNodes)
	heights := make([]int, nNodes)
	countPersHashed := make([]uint64, nNodes)

	// the lastSeg is written into the Hasher h,
	// to handle full/not full segments correctly.
	lastSegSz := sz % segment
	if lastSegSz == 0 {
		lastSegSz = segment
	}
	lastSeg := make([]byte, lastSegSz)

	nW := int(nWorkers)
	for worker := 0; worker < nW; worker++ {

		go func(worker int) {
			defer func() {
				wg.Done()
			}()

			f, err := os.OpenFile(path, os.O_RDONLY, 0)
			panicOn(err)
			defer f.Close()

			var job *job
			var ok bool
			for {
				select {
				case job, ok = <-work:
					if !ok {
						return
					}
				}
				f.Seek(job.beg, 0)
				lenseg := job.endx - job.beg
				if lenseg == 0 {
					panic("lenseg should not be 0")
				}

				nr, err := io.ReadFull(f, buf[worker][:lenseg])
				// either io.EOF (0 bytes) or
				// io.ErrUnexpectedEOF (nr<lenseg) are problems.
				panicOn(err)

				if int64(nr) != lenseg {
					panic(fmt.Sprintf("short read!?!: path = '%v'. "+
						"expected = %v; got = %v; on worker=%v",
						path, lenseg, nr, worker))
				}

				i := job.nodeK
				if job.isLast {
					// point to the last segment so
					// the main goro can inject it into Hasher.
					lastSeg = buf[worker][:lenseg]

					// Since our buf is now spoken for,
					// we must return immediately; we cannot take
					// on any other jobs/use buf[worker]. Since jobs
					// are queued in sequential order,
					// there should not be any others
					// after the last anyway. But just
					// in case the job organization
					// logic changes:
					return

				} else {

					cvs[i], _, heights[i], _, countPersHashed[i] =
						oneCoreCV(
							buf[worker][:lenseg],
							uint64(job.beg/guts.ChunkSize),
							keyWords,
							flags,
						)
				}

			}
		}(int(worker))
	}

	// send off all the jobs
	last := len(cvs) - 1
	for i := range cvs {
		beg := int64(i) * segment
		endx := int64(i+1) * segment
		if endx > sz {
			endx = sz
		}
		if endx == beg {
			panic("logic error: must have endx > beg. don't process empty segment")
		}
		job := &job{
			beg:    beg,
			endx:   endx,
			nodeK:  i,
			isLast: i == last,
		}
		work <- job
	}
	// we have sent off njob = nNodes to be hashed
	close(work)
	wg.Wait()

	// write into Hasher h
	last = len(cvs) - 1
	for j := range cvs {
		if j == last {
			// partial/full last segment
			h.Write(lastSeg)
		} else {
			// full segment
			i := heights[j]
			cv := cvs[j]
			for h.hasSubtreeAtHeight(i) {
				cv = guts.ChainingValue(guts.ParentNode(h.stack[i], cv, &h.key, h.flags))
				i++
			}
			h.stack[i] = cv
			h.counter += countPersHashed[j]
		}
	}
	sum = h.Sum(nil)
	return
}

// oneCoreCV returns the Chaining Value
// and guts.Node for the well-aligned, compressed buf.
// It is an internal implementation detail.
//
// We panic if len(buf) == 0.
//
// The baseChunkCounter describes where buf starts
// in the larger context of its origin file:
// at which 1024 byte chunk does buf start?
// This is an input to the hash, per the spec.
// This also reminds us that buf
// _must_ begin at some 1024 byte
// offset from the start of the file.
//
// The keyWords and flags are passed to the
// CompressBuffer and ParentNode calls
// to enable keyed hashing. See the
// usage in HashFile2 for details. If you
// are not keying, simply pass guts.IV and 0
// for keyWords and flags respectively.
func oneCoreCV(buf []byte, baseChunkCounter uint64, keyWords [8]uint32, flags uint32) (cvTop [8]uint32, topNode guts.Node, height int, chunkIndex, countPersHashed uint64) {

	if len(buf) == 0 {
		panic("len(buf) must be > 0")
	}
	const per = guts.MaxSIMD * guts.ChunkSize

	numCVs := (len(buf) + per - 1) / per
	// INVAR: numCVs >= 1 because len(buf) >= 1.

	cvs := make([][8]uint32, numCVs)
	nodes := make([]guts.Node, len(cvs))

	for i := range cvs {
		b := buf[i*per:]
		n := per
		if len(b) < per {
			// zero out the rest of the unused bytes
			// in a per-sized portion by allocating them.
			b = make([]byte, per)
			n = copy(b, buf[i*per:])
		} else {
			countPersHashed++
		}
		chunkIndex = baseChunkCounter + uint64(i*guts.MaxSIMD) // the chunk index.
		node := guts.CompressBuffer((*[per]byte)(b), n, &keyWords, chunkIndex, flags)
		cvs[i] = guts.ChainingValue(node)
		nodes[i] = node
	}

	// merge subtrees
	for numCVs > 2 {
		rem := numCVs / 2
		for i := range cvs[:rem] {
			parNode := guts.ParentNode(cvs[i*2], cvs[i*2+1], &keyWords, flags)
			cvs[i] = guts.ChainingValue(parNode)
			nodes[i] = parNode
		}
		if numCVs%2 != 0 {
			cvs[rem] = cvs[rem*2]
			nodes[rem] = nodes[rem*2]
			rem++
		}
		numCVs = rem
		height++
	}
	switch numCVs {
	case 2:
		topNode = guts.ParentNode(cvs[0], cvs[1], &keyWords, flags)
		cvTop = guts.ChainingValue(topNode)
		height++
	case 1:
		cvTop = cvs[0]
		topNode = nodes[0]
	}
	return
}

// Sum512Parallel computes the unkeyed
// Blake3 512-bit hash of the data in parallel
// for speed.
func Sum512Parallel(data []byte) []byte {
	return Sum512Parallel2(data, 19)
}

// Sum512Parallel2 computes the unkeyed
// Blake3 512-bit hash of the data in parallel
// for speed. The parallelBits allows varying
// the amount of hashing work that each goroutine
// does.
//
// The data will be split into (1 << parallelBits) sized
// segments, each processed in parallel, and the
// resulting set of CVs (Chaining Values) will be merged
// into the final hash.
//
// If parallelBits is < 14 then parallelBits = 14
// is assumed and used, since this is the guts.MaxSIMD * guts.ChunkSize
// amount of data that the SIMD code is optimized for.
//
// Setting the minimum parallelBits == 14 does
// the most amount of work
// in parallel, but this is typically slower overall
// than having each goroutine process a larger
// subset of the data at once.
//
// The optimal settings will depend on your local
// hardware, and in particular on the relative bandwidth
// and parallelism provided by your disk, memory, and CPU.
//
// On my hardware, somewhere between
// parallelBits = 18 (for 256KB segments)
// and parallelBits = 20 (for 1MB segments) appears
// to be fastest for hashing gigabyte
// and greater size files.
//
// Your mileage may vary.
func Sum512Parallel2(data []byte, parallelBits int) []byte {

	const per = guts.MaxSIMD * guts.ChunkSize
	if parallelBits <= 0 {
		parallelBits = 19
	}
	if parallelBits < 14 {
		parallelBits = 14
	}
	segment := 1 << parallelBits
	if segment < per {
		segment = per
	}

	if len(data) <= per {
		out := Sum512(data)
		return out[:]
	}

	cvs := make([][8]uint32, (len(data)+segment-1)/segment)
	nodes := make([]guts.Node, len(cvs))

	var wg sync.WaitGroup
	for i := range cvs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			beg := i * segment
			endx := (i + 1) * segment
			if endx > len(data) {
				endx = len(data)
			}
			b := data[beg:endx]
			cvs[i], nodes[i], _, _, _ = oneCoreCV(
				b, uint64(beg/guts.ChunkSize), guts.IV, 0)
		}(i)
	}
	wg.Wait()
	// merge subtrees
	numCVs := len(cvs)
	for numCVs > 2 {
		rem := numCVs / 2
		for i := range cvs[:rem] {
			parNode := guts.ParentNode(cvs[i*2], cvs[i*2+1], &guts.IV, 0)
			cvs[i] = guts.ChainingValue(parNode)
			nodes[i] = parNode
		}
		if numCVs%2 != 0 {
			cvs[rem] = cvs[rem*2]
			nodes[rem] = nodes[rem*2]
			rem++
		}
		numCVs = rem
	}

	switch numCVs {
	case 2:
		par := guts.ParentNode(cvs[0], cvs[1], &guts.IV, 0)
		par.Flags |= guts.FlagRoot // has both parent and root flags set now.
		out := guts.WordsToBytes(guts.CompressNode(par))
		return out[:]

	case 1:
		root := nodes[0]
		root.Flags |= guts.FlagRoot
		// WordsToBytes returns [64]byte
		out := guts.WordsToBytes(guts.CompressNode(root))
		return out[:]
	default:
		panic("should only be 1 or 2 nodes left after merge!")
	}
}

func panicOn(err error) {
	if err != nil {
		panic(err)
	}
}
