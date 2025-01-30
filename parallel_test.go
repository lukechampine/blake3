package blake3

import (
	"bytes"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"lukechampine.com/blake3/guts"
)

func TestSmallMerge(t *testing.T) {

	const base = guts.MaxSIMD * guts.ChunkSize
	chunk0 := make([]byte, guts.MaxSIMD*guts.ChunkSize)
	chunk1 := make([]byte, guts.MaxSIMD*guts.ChunkSize) // 16 = guts.MaxSIMD
	for i := range chunk1 {
		chunk1[i] = 0xff
	}
	chunk2 := make([]byte, guts.MaxSIMD*guts.ChunkSize) // 16 = guts.MaxSIMD
	for i := range chunk2 {
		chunk2[i] = byte(i % 256)
	}

	//chunk0 = chunk0[:129]
	//chunk1 = chunk1[:4713]

	h0 := New(64, nil)
	h0.Write(chunk0)
	sum0 := h0.Sum(nil)
	//vv("sum0 = '%#v'", sum0)
	//vv("h0   = '%#v'", h0)

	sum0b := h0.Sum(nil)
	//vv("sum0b = '%#v'", sum0b)
	if !bytes.Equal(sum0b, sum0) {
		t.Fatalf("Sum should be idempotent, no?")
	}
	//vv("past idem check for h0.Sum(nil)")

	h1 := New(64, nil)
	h1.Write(chunk1)
	sum1 := h1.Sum(nil)
	//vv("sum1 = '%#v'", sum1)

	// <= 16K okay?
	lel0 := Sum512Parallel2(chunk0, 14)
	//vv("lel0 = '%#x'", lel0)
	if !bytes.Equal(lel0, sum0) {
		panic("lel0 != sum0")
	}
	//vv("after computing lel0, how does par/root compare to h0? h0 is '%#v'", h0)

	lel1 := Sum512Parallel2(chunk1, 14)
	//vv("lel1 = '%#x'", lel1)
	if !bytes.Equal(lel1, sum1) {
		panic("lel1 != sum1")
	}

	//vv("ok on the 16KB single span")

	//vv("begin PARALLEL !")

	data := make([]byte, 0, 3*base)
	data = append(data, chunk0...) // actually 16KB not 1KB worth of chunks
	data = append(data, chunk1...)
	data = append(data, chunk2...)

	lel := Sum512Parallel2(data, 16)
	sumObserved := lel[:]

	hExpect := New(64, nil)
	hExpect.Write(data)
	//fmt.Printf("done with hExpect.Write(chunk0): '%#v'\n", hExpect)
	sumExpected := hExpect.Sum(nil)
	_ = sumExpected

	if !bytes.Equal(sumObserved, sumExpected) {
		t.Fatalf("Merge failed.\n Got:  '%x'; but\n want: '%x'", sumObserved, sumExpected)
	}
}

func TestBigMerge(t *testing.T) {

	t0 := time.Now()
	var seed [32]byte
	seed[0] = 5

	//for k := 0; k < 31; k++ {
	// for fast day to day testing, just validate one size. 32MB.
	for k := 25; k < 26; k++ {

		// deterministic pseudo-random numbers as data.
		generator := New(64, seed[:])
		data := make([]byte, 1<<k)

		generator.XOF().Read(data)
		elapRandom := time.Since(t0)
		_ = elapRandom

		//vv("time to generate random data = '%v'", elapRandom)

		t0 = time.Now()
		h0 := New(64, nil)
		h0.Write(data)
		sum0 := h0.Sum(nil)
		elap0 := time.Since(t0)
		_ = elap0
		//vv("orig Blake3 New/Sum(nil) compute time = '%v'; ", elap0)

		for i := 14; i <= 24; i++ {
			t1 := time.Now()
			lel := Sum512Parallel2(data, i)
			elap1 := time.Since(t1)

			sumObserved := lel[:]
			if !bytes.Equal(sumObserved, sum0) {
				t.Fatalf("Merge failed.\n Got:  '%x'; but\n want: '%x'", sumObserved, sum0)
			}
			fmt.Printf("parallel segBits = %v  =>  %v  (%0.2f x speedup)\n",
				i, elap1, float64(elap0)/float64(elap1))
		}
	} // k loop

	// Ignoring disk, mac does best at 19 bits; 512KB
	// parallel segBits = 14  =>  117.470199ms  (3.21 x speedup)
	// parallel segBits = 15  =>  87.613051ms  (4.31 x speedup)
	// parallel segBits = 16  =>  73.345909ms  (5.15 x speedup)
	// parallel segBits = 17  =>  69.810899ms  (5.41 x speedup)
	// parallel segBits = 18  =>  66.965459ms  (5.64 x speedup)
	// parallel segBits = 19  =>  64.883706ms  (5.82 x speedup)
	// parallel segBits = 20  =>  68.4841ms  (5.51 x speedup)
	// parallel segBits = 21  =>  67.292666ms  (5.61 x speedup)
	// parallel segBits = 22  =>  74.68442ms  (5.05 x speedup)
	// parallel segBits = 23  =>  79.767926ms  (4.73 x speedup)
	// parallel segBits = 24  =>  74.956038ms  (5.04 x speedup)

	// Linux, 48 cores, also does best at 19 or 21 bits, so use 19.
	// parallel segBits = 14  =>  170.105834ms  (2.65 x speedup)
	// parallel segBits = 15  =>  88.193593ms  (5.10 x speedup)
	// parallel segBits = 16  =>  39.2206ms  (11.47 x speedup)
	// parallel segBits = 17  =>  25.221818ms  (17.84 x speedup)
	// parallel segBits = 18  =>  21.495614ms  (20.93 x speedup)
	// parallel segBits = 19  =>  21.194702ms  (21.23 x speedup)
	// parallel segBits = 20  =>  21.930639ms  (20.52 x speedup)
	// parallel segBits = 21  =>  21.125441ms  (21.30 x speedup)
	// parallel segBits = 22  =>  22.625609ms  (19.89 x speedup)
	// parallel segBits = 23  =>  24.649581ms  (18.25 x speedup)
	// parallel segBits = 24  =>  29.267046ms  (15.37 x speedup)
	// --- PASS: TestBigMerge (1.38s)

}

func TestHashFile(t *testing.T) {

	path := ".tmp.10841"
	os.Remove(path)
	defer os.Remove(path) // cleanup

	t0 := time.Now()
	var seed [32]byte
	seed[0] = 5

	for k := 0; k < 31; k++ {
		if k != 25 {
			// for fast day to day testing, just validate 32MB.
			// Comment this out for more rigorous testing.
			continue
		}

		// deterministic pseudo-random numbers as data.
		generator := New(64, seed[:])
		data := make([]byte, 1<<k)

		mykey := make([]byte, 32)

		generator.XOF().Read(data)
		generator.XOF().Read(mykey)

		elapRandom := time.Since(t0)
		_ = elapRandom

		// shunt random data out to the test file.
		rfd, err := os.Create(path)
		panicOn(err)
		_, err = rfd.Write(data)
		panicOn(err)
		rfd.Close()

		//vv("time to generate random data = '%v'", elapRandom)

		t0 = time.Now()
		by, err := os.ReadFile(path)
		panicOn(err)
		h0 := New(64, nil)
		h0.Write(by)

		//vv("h0.counter = '%v'/'%b' before Sum.", h0.counter, h0.counter)
		//vv("h0 before Sum: '%#v'", h0)
		//if bytes.Equal(h0.buf[:], by[(len(by)-len(h0.buf)):len(by)]) {
		//	vv("h0.buf has the last bytes of by")
		//}
		sum0 := h0.Sum(nil)
		//vv("h0.counter after Sum: '%v'/'%b'", h0.counter, h0.counter)
		//vv("h0 after Sum: '%#v'", h0)
		elap0 := time.Since(t0)

		// and keyed version
		hk := New(64, mykey)
		hk.Write(by)
		sumKeyed := hk.Sum(nil)

		//vv("orig Blake3 New/Sum(nil) compute time = '%v'; ", elap0)

		t1 := time.Now()
		parbits := 19
		//lel := Sum512Parallel(data, parbits)
		lel, _, err := HashFile(path)
		panicOn(err)
		elap1 := time.Since(t1)

		sumObserved := lel[:]
		if !bytes.Equal(sumObserved, sum0) {
			t.Fatalf("Merge failed.\n Got:  '%x'; but\n want: '%x'",
				sumObserved, sum0)
		}
		fmt.Printf("parallel segBits = %v  =>  %v  (%0.2f x speedup)\n",
			parbits, elap1, float64(elap0)/float64(elap1))

		// keyed version
		lelk, _, err := HashFile2(path, mykey, 0, 0)
		panicOn(err)

		sumObservedKeyed := lelk[:]
		if !bytes.Equal(sumObservedKeyed, sumKeyed) {
			t.Fatalf("Keyed HashFile failed.\n Got:  '%x'; but\n want: '%x'",
				sumObservedKeyed, sumKeyed)
		}
	}
}

// almost verbatim Luke Champine's advice in
// https://github.com/lukechampine/blake3/issues/22#issuecomment-2626216794
func sum512ParallelOrig(buf []byte) []byte {
	const per = guts.MaxSIMD * guts.ChunkSize
	if len(buf) <= per {
		//out := Sum256(buf)
		out := Sum512(buf)
		return out[:]
	}
	//vv("per = %v", per)
	cvs := make([][8]uint32, (len(buf)+per-1)/per)
	var wg sync.WaitGroup
	for i := range cvs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			b := buf[i*per:]
			n := per
			if len(b) < per {
				b = make([]byte, per)
				n = copy(b, buf[i*per:])
			}
			cvs[i] = guts.ChainingValue(guts.CompressBuffer((*[per]byte)(b), n, &guts.IV, uint64(i*guts.MaxSIMD), 0))
			//vv("Orig used counter = '%v' -> cvs[%v] = '%#v'", uint64(i*guts.MaxSIMD), i, cvs[i])
		}(i)
	}
	wg.Wait()
	// merge subtrees
	numCVs := len(cvs)
	for numCVs > 2 {
		rem := numCVs / 2
		for i := range cvs[:rem] {
			cvs[i] = guts.ChainingValue(guts.ParentNode(cvs[i*2], cvs[i*2+1], &guts.IV, 0))
		}
		if numCVs%2 != 0 {
			cvs[rem] = cvs[rem*2]
			rem++
		}
		numCVs = rem
	}
	out := guts.WordsToBytes(guts.CompressNode(guts.ParentNode(cvs[0], cvs[1], &guts.IV, guts.FlagRoot)))

	// return *(*[32]byte)(out[:])
	return out[:]
}

func TestOneCoreCV(t *testing.T) {

	// match Sum() and rootNode() after a set of Writes and
	// the equivalent oneCoreCV().

	const per = guts.MaxSIMD * guts.ChunkSize

	path := ".tmp.108422"
	os.Remove(path)
	defer os.Remove(path) // cleanup

	beg := (1 << 19) - 1
	endx := (1<<19)*25 + 2
	incr := 1 << 17
	_, _, _ = beg, endx, incr
	for j := beg; j < endx; j += incr {

		//vv("file of size %v", j)

		// exactly one buffer worth
		data := make([]byte, j)
		for i := range data {
			data[i] = 0xff
		}

		// write to file for HashFile below

		os.Remove(path)
		rfd, err := os.Create(path)
		panicOn(err)
		_, err = rfd.Write(data)
		panicOn(err)
		rfd.Close()

		// positive control to match
		h0 := New(64, nil)
		h0.Write(data)
		sum0 := h0.Sum(nil)

		lel, h2, err := HashFile2(path, nil, 0, 0)
		panicOn(err)

		sumObserved := lel[:]
		if !bytes.Equal(sumObserved, sum0) {
			t.Fatalf("parallel failed.\n Got:  '%x'; but\n want: '%x'",
				sumObserved, sum0)
		}

		sum2 := h2.Sum(nil)
		//fmt.Printf("sum0 = '%x'\n", sum0)
		//fmt.Printf("sum2 = '%x'\n", sum2)
		//fmt.Printf("lel  = '%x'\n", lel[:])
		if !bytes.Equal(sum2, sum0) {
			t.Fatalf("h2 Hasher sum2 != sum0 \n Got:  '%x'; but\n want: '%x'",
				sum2, sum0)
		}
		//vv("good: sum2 matches sum1")
		if !bytes.Equal(sumObserved, sum2) {
			t.Fatalf("h2 Hasher update failed.\n Got:  '%x'; but\n want: '%x'",
				sum2, sumObserved)
		}
	}
}
