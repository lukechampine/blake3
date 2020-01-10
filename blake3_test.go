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

func TestVectors(t *testing.T) {
	data, err := ioutil.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Key   string
		Cases []struct {
			InputLen  int    `json:"input_len"`
			Hash      string `json:"hash"`
			KeyedHash string `json:"keyed_hash"`
			DeriveKey string `json:"derive_key"`
		}
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}

	input := make([]byte, 1<<15)
	for i := range input {
		input[i] = byte(i % 251)
	}

	for _, vec := range vectors.Cases {
		in := input[:vec.InputLen]
		// regular
		h := blake3.New(len(vec.Hash)/2, nil)
		h.Write(in)
		if out := toHex(h.Sum(nil)); out != vec.Hash {
			t.Errorf("output did not match test vector:\n\texpected: %v...\n\t     got: %v...", vec.Hash[:10], out[:10])
		}
		// keyed
		h = blake3.New(len(vec.KeyedHash)/2, []byte(vectors.Key))
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
		// XOF should produce identical results, even when outputting 7 bytes at a time
		h = blake3.New(len(vec.Hash)/2, nil)
		h.Write(in)
		var xofBuf bytes.Buffer
		io.CopyBuffer(&xofBuf, io.LimitReader(h.XOF(), int64(len(vec.Hash)/2)), make([]byte, 7))
		if out := toHex(xofBuf.Bytes()); out != vec.Hash {
			t.Errorf("XOF output did not match test vector:\n\texpected: %v...\n\t     got: %v...", vec.Hash[:10], out[:10])
		}
	}
}

func BenchmarkWrite(b *testing.B) {
	h := blake3.New(32, nil)
	buf := make([]byte, 1<<15)
	b.SetBytes(int64(len(buf)))
	for i := 0; i < b.N; i++ {
		h.Write(buf)
	}
}

func BenchmarkChunk(b *testing.B) {
	h := blake3.New(32, nil)
	buf := make([]byte, 1024)
	out := make([]byte, 0, 32)
	for i := 0; i < b.N; i++ {
		h.Write(buf)
		h.Sum(out)
	}
}

func BenchmarkXOF(b *testing.B) {
	b.SetBytes(1)
	io.CopyN(ioutil.Discard, blake3.New(32, nil).XOF(), int64(b.N))
}
