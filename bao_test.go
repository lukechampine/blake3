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

	interleaved, root := blake3.BaoEncodeBuf(data, 0, false)
	if toHex(root[:]) != "6654fbd1836b531b25e2782c9cc9b792c80abb36b024f59db5d5f6bd3187ddfe" {
		t.Errorf("bad root: %x", root)
	} else if !bytes.Equal(interleaved, goldenInterleaved) {
		t.Error("bad interleaved encoding")
	}

	outboard, root := blake3.BaoEncodeBuf(data, 0, true)
	if toHex(root[:]) != "6654fbd1836b531b25e2782c9cc9b792c80abb36b024f59db5d5f6bd3187ddfe" {
		t.Errorf("bad root: %x", root)
	} else if !bytes.Equal(outboard, goldenOutboard) {
		t.Error("bad outboard encoding")
	}

	// test empty input
	interleaved, root = blake3.BaoEncodeBuf(nil, 0, false)
	if toHex(root[:]) != "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262" {
		t.Errorf("bad root: %x", root)
	} else if toHex(interleaved[:]) != "0000000000000000" {
		t.Errorf("bad interleaved encoding: %x", interleaved)
	} else if !blake3.BaoVerifyBuf(interleaved, nil, 0, root) {
		t.Error("verify failed")
	}
	outboard, root = blake3.BaoEncodeBuf(nil, 0, true)
	if toHex(root[:]) != "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262" {
		t.Errorf("bad root: %x", root)
	} else if toHex(outboard[:]) != "0000000000000000" {
		t.Errorf("bad outboard encoding: %x", outboard)
	} else if !blake3.BaoVerifyBuf(nil, outboard, 0, root) {
		t.Error("verify failed")
	}
}

func TestBaoInterleaved(t *testing.T) {
	data := make([]byte, 1<<20)
	blake3.New(0, nil).XOF().Read(data)

	for group := 0; group < 10; group++ {
		interleaved, root := blake3.BaoEncodeBuf(data, group, false)
		if !blake3.BaoVerifyBuf(interleaved, nil, group, root) {
			t.Fatal("verify failed")
		}
		badRoot := root
		badRoot[0] ^= 1
		if blake3.BaoVerifyBuf(interleaved, nil, group, badRoot) {
			t.Fatal("verify succeeded with bad root")
		}
		badPrefix := append([]byte(nil), interleaved...)
		badPrefix[0] ^= 1
		if blake3.BaoVerifyBuf(badPrefix, nil, group, root) {
			t.Fatal("verify succeeded with bad length prefix")
		}
		badCVs := append([]byte(nil), interleaved...)
		badCVs[8] ^= 1
		if blake3.BaoVerifyBuf(badCVs, nil, group, root) {
			t.Fatal("verify succeeded with bad cv data")
		}
		badData := append([]byte(nil), interleaved...)
		badData[len(badData)-1] ^= 1
		if blake3.BaoVerifyBuf(badData, nil, group, root) {
			t.Fatal("verify succeeded with bad content")
		}
		extraData := append(append([]byte(nil), interleaved...), 1, 2, 3)
		if blake3.BaoVerifyBuf(extraData, nil, group, root) {
			t.Fatal("verify succeeded with extra data")
		}
	}
}

func TestBaoOutboard(t *testing.T) {
	data := make([]byte, 1<<20)
	blake3.New(0, nil).XOF().Read(data)

	for group := 0; group < 10; group++ {
		outboard, root := blake3.BaoEncodeBuf(data, group, true)
		if !blake3.BaoVerifyBuf(data, outboard, group, root) {
			t.Fatal("verify failed")
		}
		badRoot := root
		badRoot[0] ^= 1
		if blake3.BaoVerifyBuf(data, outboard, group, badRoot) {
			t.Fatal("verify succeeded with bad root")
		}
		badPrefix := append([]byte(nil), outboard...)
		badPrefix[0] ^= 1
		if blake3.BaoVerifyBuf(data, badPrefix, group, root) {
			t.Fatal("verify succeeded with bad length prefix")
		}
		badCVs := append([]byte(nil), outboard...)
		badCVs[8] ^= 1
		if blake3.BaoVerifyBuf(data, badCVs, group, root) {
			t.Fatal("verify succeeded with bad cv data")
		}
	}
}
