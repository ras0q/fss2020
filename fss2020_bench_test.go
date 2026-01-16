package fss2020_test

import (
	"math/big"
	"testing"

	"github.com/ras0q/fss2020"
)

// $ go test -bench . -benchmem
// goos: linux
// goarch: amd64
// pkg: github.com/ras0q/fss2020
// cpu: Intel(R) Core(TM) i7-8565U CPU @ 1.80GHz
// BenchmarkGenerateKeys-8            31772             38988 ns/op           49064 B/op        633 allocs/op
// BenchmarkEvaluate-8                66466             19521 ns/op           21928 B/op        195 allocs/op
// PASS
// ok      github.com/ras0q/fss2020        2.545s

func BenchmarkGenerateKeys(b *testing.B) {
	const (
		n      = 16 // 16-bit integers
		lambda = 128
		alpha  = 12345
		beta   = 1
	)

	groupOrder := new(big.Int).Lsh(big.NewInt(1), 16)
	dcfScheme := fss2020.NewDCFScheme(lambda, groupOrder)

	for b.Loop() {
		_, _, err := dcfScheme.GenerateKeys(n, alpha, beta)
		if err != nil {
			b.Fatalf("GenerateKeys failed: %v", err)
		}
	}
}

func BenchmarkEvaluate(b *testing.B) {
	const (
		n      = 16 // 16-bit integers
		lambda = 128
		alpha  = 12345
		beta   = 1
		x      = 20000
	)

	groupOrder := new(big.Int).Lsh(big.NewInt(1), 16)
	dcfScheme := fss2020.NewDCFScheme(lambda, groupOrder)

	key0, _, err := dcfScheme.GenerateKeys(n, alpha, beta)
	if err != nil {
		b.Fatalf("Setup failed: GenerateKeys failed: %v", err)
	}

	for b.Loop() {
		_, err := dcfScheme.Evaluate(key0, x)
		if err != nil {
			b.Fatalf("Evaluate failed: %v", err)
		}
	}
}
