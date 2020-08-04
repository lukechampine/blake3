// +build !darwin

package blake3

import "github.com/klauspost/cpuid"

var (
	haveAVX2   = cpuid.CPU.AVX2()
	haveAVX512 = cpuid.CPU.AVX512F()
)
