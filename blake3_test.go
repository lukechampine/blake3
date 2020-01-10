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
	input := make([]byte, 1<<15)
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
			t.Errorf("output did not match test vector:\n\texpected: %v...\n\t     got: %v...", vec.DeriveKey[:10], subKey[:10])
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
}

type nopReader struct{}

func (nopReader) Read(p []byte) (int, error) { return len(p), nil }

func BenchmarkWrite(b *testing.B) {
	b.SetBytes(1)
	io.CopyN(blake3.New(0, nil), nopReader{}, int64(b.N))
}

func BenchmarkSum256(b *testing.B) {
	buf := make([]byte, 1024)
	for i := 0; i < b.N; i++ {
		blake3.Sum256(buf)
	}
}

func BenchmarkXOF(b *testing.B) {
	b.SetBytes(1)
	io.CopyN(ioutil.Discard, blake3.New(0, nil).XOF(), int64(b.N))
}
