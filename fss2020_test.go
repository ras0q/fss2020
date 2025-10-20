package fss2020_test

import (
	"log/slog"
	"math/big"
	"testing"

	"github.com/ras0q/fss2020"
)

func TestDCFScheme(t *testing.T) {
	const (
		n      = 8
		lambda = 128
		beta   = 1
	)

	groupOrder := new(big.Int).Lsh(big.NewInt(1), 16)
	dcfScheme := fss2020.NewDCFScheme(lambda, groupOrder)

	testCases := []struct {
		name  string
		alpha int
		x     int
		want  int
	}{
		{
			name:  "x < alpha, should be beta",
			alpha: 10,
			x:     5,
			want:  beta,
		},
		{
			name:  "x (<0) < alpha, should be beta",
			alpha: 10,
			x:     -5,
			want:  beta,
		},
		{
			name:  "x == alpha, should be 0",
			alpha: 10,
			x:     10,
			want:  0,
		},
		{
			name:  "x == alpha (<0), should be 0",
			alpha: -10,
			x:     -10,
			want:  0,
		},
		{
			name:  "x > alpha, should be 0",
			alpha: 10,
			x:     15,
			want:  0,
		},
		{
			name:  "x > alpha (<0), should be 0",
			alpha: -10,
			x:     15,
			want:  0,
		},
		{
			name:  "x (<0) > alpha (<0), should be 0",
			alpha: -10,
			x:     -5,
			want:  0,
		},
		{
			name:  "edge case: alpha = 0, x = 0",
			alpha: 0,
			x:     0,
			want:  0,
		},
		{
			name:  "edge case: alpha = 0, x > 0",
			alpha: 0,
			x:     1,
			want:  0,
		},
		{
			name:  "edge case: alpha max, x < alpha",
			alpha: (1 << (n - 1)) - 1,
			x:     0,
			want:  beta,
		},
		{
			name:  "edge case: alpha max, x == alpha",
			alpha: (1 << (n - 1)) - 1,
			x:     (1 << (n - 1)) - 1,
			want:  0,
		},
	}

	slog.SetLogLoggerLevel(slog.LevelDebug)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key0, key1, err := dcfScheme.GenerateKeys(n, tc.alpha, beta)
			if err != nil {
				t.Fatalf("GenerateKeys failed: %v", err)
			}

			y0, err := dcfScheme.Evaluate(key0, tc.x)
			if err != nil {
				t.Fatalf("Evaluate for key0 failed: %v", err)
			}

			y1, err := dcfScheme.Evaluate(key1, tc.x)
			if err != nil {
				t.Fatalf("Evaluate for key1 failed: %v", err)
			}

			result := dcfScheme.Reconstruct(y0, y1)
			wantBigInt := big.NewInt(int64(tc.want))

			if result.Cmp(wantBigInt) != 0 {
				t.Errorf("f0(x) + f1(x) = %v, want %v", result, wantBigInt)
			}
		})
	}
}
