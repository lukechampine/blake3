package blake3_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
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

func TestBaoChunkGroup(t *testing.T) {
	// from https://github.com/n0-computer/abao/blob/9b756ec8097afc782d76f7aec0a5ac9f4b82329a/tests/test_vectors.json
	const group = 4 // 16 KiB
	baoInput := func(n int) (in []byte) {
		for i := uint32(1); len(in) < n; i++ {
			in = binary.LittleEndian.AppendUint32(in, i)
		}
		return in[:n]
	}
	for _, test := range []struct {
		inputLen int
		exp      string
	}{
		{0, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"},
		{1, "48fc721fbbc172e0925fa27af1671de225ba927134802998b10a1568a188652b"},
		{1023, "15f8c1ae1049fe7e837186612c8ce732e66835841a4569b71e4ac3e3d3411b90"},
		{1024, "f749c19181983b839cd97fe121cebaf076bc951e8c8e6d64accfedad5951ec22"},
		{1025, "3613596275c4ea790774dedf20835b2daf86cacc892feef6ce720c121572f1f9"},
		{16383, "f0970fbfe2f1c5145fa6aa31833779803d5c53743a8443ed1395218f511834ba"},
		{16384, "b318758645c4467406c829a5f3da7cab00010fccccf4b7c314525cd85e2d0af8"},
		{16385, "12a6a6b0554e7f3eed485f668bfd3b37382a2beee5e7ed5594c4a91c4c70f4aa"},
		{32768, "8008de557073cab60f851191359ad9dc1afe9dc6152668ee01825c56ac5a754e"},
		{49152, "91823357fefc308b57bb85ebed1d1edeba3c355e804dc63fa98fcb82554b1566"},
		{180224, "4742cbae9485ce1b86ab359c1a84e203f819795d018b22a5c70c5c4577dd732e"},
		{212992, "760c549edfe95c734b1d6a9b846d81692ed3ca022b541442949a0e42fe570df2"},
	} {
		input := baoInput(test.inputLen)
		_, root := blake3.BaoEncodeBuf(input, group, false)
		if out := fmt.Sprintf("%x", root); out != test.exp {
			t.Errorf("output %v did not match test vector:\n\texpected: %v...\n\t     got: %v...", test.inputLen, test.exp[:10], out[:10])
		}
	}
}

func TestBaoStreaming(t *testing.T) {
	data := make([]byte, 1<<20)
	blake3.New(0, nil).XOF().Read(data)

	enc, root := blake3.BaoEncodeBuf(data, 0, false)
	if root != blake3.Sum256(data) {
		t.Fatal("bad root")
	}
	var buf bytes.Buffer
	if ok, err := blake3.BaoDecode(&buf, bytes.NewReader(enc), nil, 0, root); err != nil || !ok {
		t.Fatal("decode failed")
	} else if !bytes.Equal(buf.Bytes(), data) {
		t.Fatal("bad decode")
	}

	// corrupt root; nothing should be written to buf
	buf.Reset()
	if ok, err := blake3.BaoDecode(&buf, bytes.NewReader(enc), nil, 0, [32]byte{}); err != nil {
		t.Fatal("decode failed")
	} else if ok {
		t.Fatal("decode succeeded with bad root")
	} else if buf.Len() != 0 {
		t.Fatal("buf was written with bad root")
	}

	// corrupt a byte halfway through; buf should only be partially written
	buf.Reset()
	enc[len(enc)/2] ^= 1
	if ok, err := blake3.BaoDecode(&buf, bytes.NewReader(enc), nil, 0, root); err != nil {
		t.Fatal("decode failed")
	} else if ok {
		t.Fatal("decode succeeded with bad data")
	} else if !bytes.Equal(buf.Bytes(), data[:buf.Len()]) {
		t.Fatal("invalid data was written to buf")
	}
}
