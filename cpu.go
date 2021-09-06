// +build !darwin

package blake3

import "github.com/klauspost/cpuid/v2"

var (
	haveAVX2   = cpuid.CPU.AVX2()
	haveAVX512 = cpuid.CPU.AVX512F()
)
