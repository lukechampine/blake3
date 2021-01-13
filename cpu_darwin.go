package blake3

import (
	"syscall"

	"github.com/klauspost/cpuid"
)

var (
	haveAVX2   bool
	haveAVX512 bool
)

func init() {
	haveAVX2 = cpuid.CPU.AVX2()
	haveAVX512 = cpuid.CPU.AVX512F()
	if !haveAVX512 {
		// On some Macs, AVX512 detection is buggy, so fallback to sysctl
		b, _ := syscall.Sysctl("hw.optional.avx512f")
		haveAVX512 = len(b) > 0 && b[0] == 1
	}
}
