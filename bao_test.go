package blake3_test

import (
	"bytes"
	"os"
	"testing"

	"lukechampine.com/blake3"
)

func TestBaoGolden(t *testing.T) {
	data, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	goldenInterleaved, err := os.ReadFile("testdata/bao-golden.bao")
	if err != nil {
		t.Fatal(err)
	}
	goldenOutboard, err := os.ReadFile("testdata/bao-golden.obao")
	if err != nil {
		t.Fatal(err)
	}

	interleaved, root := blake3.BaoEncodeBuf(data, false)
	if toHex(root[:]) != "6654fbd1836b531b25e2782c9cc9b792c80abb36b024f59db5d5f6bd3187ddfe" {
		t.Errorf("bad root: %x", root)
	} else if !bytes.Equal(interleaved, goldenInterleaved) {
		t.Error("bad interleaved encoding")
	}

	outboard, root := blake3.BaoEncodeBuf(data, true)
	if toHex(root[:]) != "6654fbd1836b531b25e2782c9cc9b792c80abb36b024f59db5d5f6bd3187ddfe" {
		t.Errorf("bad root: %x", root)
	} else if !bytes.Equal(outboard, goldenOutboard) {
		t.Error("bad outboard encoding")
	}

	// test empty input
	interleaved, root = blake3.BaoEncodeBuf(nil, false)
	if toHex(root[:]) != "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262" {
		t.Errorf("bad root: %x", root)
	} else if toHex(interleaved[:]) != "0000000000000000" {
		t.Errorf("bad interleaved encoding: %x", interleaved)
	} else if !blake3.BaoVerifyBuf(interleaved, nil, root) {
		t.Error("verify failed")
	}
	outboard, root = blake3.BaoEncodeBuf(nil, false)
	if toHex(root[:]) != "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262" {
		t.Errorf("bad root: %x", root)
	} else if toHex(outboard[:]) != "0000000000000000" {
		t.Errorf("bad outboard encoding: %x", outboard)
	} else if !blake3.BaoVerifyBuf(nil, outboard, root) {
		t.Error("verify failed")
	}
}

func TestBaoInterleaved(t *testing.T) {
	data, _ := os.ReadFile("testdata/vectors.json")
	interleaved, root := blake3.BaoEncodeBuf(data, false)
	if !blake3.BaoVerifyBuf(interleaved, nil, root) {
		t.Fatal("verify failed")
	}
	badRoot := root
	badRoot[0] ^= 1
	if blake3.BaoVerifyBuf(interleaved, nil, badRoot) {
		t.Fatal("verify succeeded with bad root")
	}
	badPrefix := append([]byte(nil), interleaved...)
	badPrefix[0] ^= 1
	if blake3.BaoVerifyBuf(badPrefix, nil, root) {
		t.Fatal("verify succeeded with bad length prefix")
	}
	badCVs := append([]byte(nil), interleaved...)
	badCVs[8] ^= 1
	if blake3.BaoVerifyBuf(badCVs, nil, root) {
		t.Fatal("verify succeeded with bad cv data")
	}
	badData := append([]byte(nil), interleaved...)
	badData[len(badData)-1] ^= 1
	if blake3.BaoVerifyBuf(badData, nil, root) {
		t.Fatal("verify succeeded with bad content")
	}
}

func TestBaoOutboard(t *testing.T) {
	data, _ := os.ReadFile("testdata/vectors.json")
	outboard, root := blake3.BaoEncodeBuf(data, true)
	if !blake3.BaoVerifyBuf(data, outboard, root) {
		t.Fatal("verify failed")
	}
	badRoot := root
	badRoot[0] ^= 1
	if blake3.BaoVerifyBuf(data, outboard, badRoot) {
		t.Fatal("verify succeeded with bad root")
	}
	badPrefix := append([]byte(nil), outboard...)
	badPrefix[0] ^= 1
	if blake3.BaoVerifyBuf(data, badPrefix, root) {
		t.Fatal("verify succeeded with bad length prefix")
	}
	badCVs := append([]byte(nil), outboard...)
	badCVs[8] ^= 1
	if blake3.BaoVerifyBuf(data, badCVs, root) {
		t.Fatal("verify succeeded with bad cv data")
	}
}
