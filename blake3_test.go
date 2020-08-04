package blake3_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/ioutil"
	"testing"

	"lukechampine.com/blake3"
)

func toHex(data []byte) string { return hex.EncodeToString(data) }

var testVectors = func() (vecs struct {
	Key   string
	Cases []struct {
		InputLen  int    `json:"input_len"`
		Hash      string `json:"hash"`
		KeyedHash string `json:"keyed_hash"`
		DeriveKey string `json:"derive_key"`
	}
}) {
	data, err := ioutil.ReadFile("testdata/vectors.json")
	if err != nil {
		panic(err)
	}
	if err := json.Unmarshal(data, &vecs); err != nil {
		panic(err)
	}
	return
}()

var testInput = func() []byte {
	input := make([]byte, 1e6)
	for i := range input {
		input[i] = byte(i % 251)
	}
	return input
}()

func TestVectors(t *testing.T) {
	for _, vec := range testVectors.Cases {
		in := testInput[:vec.InputLen]

		// regular
		h := blake3.New(len(vec.Hash)/2, nil)
		h.Write(in)
		if out := toHex(h.Sum(nil)); out != vec.Hash {
			t.Errorf("output did not match test vector:\n\texpected: %v...\n\t     got: %v...", vec.Hash[:10], out[:10])
		}

		// keyed
		h = blake3.New(len(vec.KeyedHash)/2, []byte(testVectors.Key))
		h.Write(in)
		if out := toHex(h.Sum(nil)); out != vec.KeyedHash {
			t.Errorf("output did not match test vector:\n\texpected: %v...\n\t     got: %v...", vec.KeyedHash[:10], out[:10])
		}

		// derive key
		const ctx = "BLAKE3 2019-12-27 16:29:52 test vectors context"
		subKey := make([]byte, len(vec.DeriveKey)/2)
		blake3.DeriveKey(subKey, ctx, in)
		if out := toHex(subKey); out != vec.DeriveKey {
			t.Errorf("output did not match test vector:\n\texpected: %v...\n\t     got: %v...", vec.DeriveKey[:10], out[:10])
		}
	}
}

func TestXOF(t *testing.T) {
	for _, vec := range testVectors.Cases {
		in := testInput[:vec.InputLen]

		// XOF should produce same output as Sum, even when outputting 7 bytes at a time
		h := blake3.New(len(vec.Hash)/2, nil)
		h.Write(in)
		var xofBuf bytes.Buffer
		io.CopyBuffer(&xofBuf, io.LimitReader(h.XOF(), int64(len(vec.Hash)/2)), make([]byte, 7))
		if out := toHex(xofBuf.Bytes()); out != vec.Hash {
			t.Errorf("XOF output did not match test vector:\n\texpected: %v...\n\t     got: %v...", vec.Hash[:10], out[:10])
		}

		// Should be able to Seek around in the output stream without affecting correctness
		seeks := []struct {
			offset int64
			whence int
		}{
			{0, io.SeekStart},
			{17, io.SeekCurrent},
			{-5, io.SeekCurrent},
			{int64(h.Size()), io.SeekStart},
			{int64(h.Size()), io.SeekCurrent},
		}
		xof := h.XOF()
		outR := bytes.NewReader(xofBuf.Bytes())
		for _, s := range seeks {
			outRead := make([]byte, 10)
			xofRead := make([]byte, 10)
			offset, _ := outR.Seek(s.offset, s.whence)
			n, _ := outR.Read(outRead)
			xof.Seek(s.offset, s.whence)
			xof.Read(xofRead[:n])
			if !bytes.Equal(outRead[:n], xofRead[:n]) {
				t.Errorf("XOF output did not match test vector at offset %v:\n\texpected: %x...\n\t     got: %x...", offset, outRead[:10], xofRead[:10])
			}
		}
	}
	// test behavior at end of stream
	xof := blake3.New(0, nil).XOF()
	buf := make([]byte, 1024)
	xof.Seek(-1000, io.SeekEnd)
	n, err := xof.Read(buf)
	if n != 1000 || err != nil {
		t.Errorf("expected (1000, nil) when reading near end of stream, got (%v, %v)", n, err)
	}
	n, err = xof.Read(buf)
	if n != 0 || err != io.EOF {
		t.Errorf("expected (0, EOF) when reading past end of stream, got (%v, %v)", n, err)
	}

	// test invalid seek offsets
	_, err = xof.Seek(-1, io.SeekStart)
	if err == nil {
		t.Error("expected invalid offset error, got nil")
	}
	xof.Seek(0, io.SeekStart)
	_, err = xof.Seek(-1, io.SeekCurrent)
	if err == nil {
		t.Error("expected invalid offset error, got nil")
	}

	// test invalid seek whence
	didPanic := func() (p bool) {
		defer func() { p = recover() != nil }()
		xof.Seek(0, 17)
		return
	}()
	if !didPanic {
		t.Error("expected panic when seeking with invalid whence")
	}
}

func TestSum(t *testing.T) {
	for _, vec := range testVectors.Cases {
		in := testInput[:vec.InputLen]

		var exp256 [32]byte
		h := blake3.New(32, nil)
		h.Write(in)
		h.Sum(exp256[:0])
		if got256 := blake3.Sum256(in); exp256 != got256 {
			t.Errorf("Sum256 output did not match Sum output:\n\texpected: %x...\n\t     got: %x...", exp256[:5], got256[:5])
		}

		var exp512 [64]byte
		h = blake3.New(64, nil)
		h.Write(in)
		h.Sum(exp512[:0])
		if got512 := blake3.Sum512(in); exp512 != got512 {
			t.Errorf("Sum512 output did not match Sum output:\n\texpected: %x...\n\t     got: %x...", exp512[:5], got512[:5])
		}
	}
}

func TestReset(t *testing.T) {
	for _, vec := range testVectors.Cases {
		in := testInput[:vec.InputLen]

		h := blake3.New(32, nil)
		h.Write(in)
		out1 := h.Sum(nil)
		h.Reset()
		h.Write(in)
		out2 := h.Sum(nil)
		if !bytes.Equal(out1, out2) {
			t.Error("Reset did not reset Hasher state properly")
		}
	}

	// gotta have 100% test coverage...
	if blake3.New(0, nil).BlockSize() != 64 {
		t.Error("incorrect block size")
	}
}

type nopReader struct{}

func (nopReader) Read(p []byte) (int, error) { return len(p), nil }

func BenchmarkWrite(b *testing.B) {
	b.ReportAllocs()
	b.SetBytes(1024)
	io.CopyN(blake3.New(0, nil), nopReader{}, int64(b.N*1024))
}

func BenchmarkXOF(b *testing.B) {
	b.ReportAllocs()
	b.SetBytes(1024)
	io.CopyN(ioutil.Discard, blake3.New(0, nil).XOF(), int64(b.N*1024))
}

func BenchmarkSum256(b *testing.B) {
	b.Run("64", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(64)
		buf := make([]byte, 64)
		for i := 0; i < b.N; i++ {
			blake3.Sum256(buf)
		}
	})
	b.Run("1024", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(1024)
		buf := make([]byte, 1024)
		for i := 0; i < b.N; i++ {
			blake3.Sum256(buf)
		}
	})
	b.Run("65536", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(65536)
		buf := make([]byte, 65536)
		for i := 0; i < b.N; i++ {
			blake3.Sum256(buf)
		}
	})
}
