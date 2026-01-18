package fss2020_test

import (
	"math/big"
	"testing"

	"github.com/ras0q/fss2020"
)

func TestDDCF(t *testing.T) {
	const (
		n      = 8
		lambda = 128
	)

	groupOrder := new(big.Int).Lsh(big.NewInt(1), 16)
	dcfScheme := fss2020.NewDCFScheme(lambda, groupOrder)

	testCases := []struct {
		name  string
		alpha int
		x     int
		beta0 int
		beta1 int
		want  int
	}{
		{
			name:  "x < alpha, should be beta0",
			alpha: 10,
			x:     5,
			beta0: 7,
			beta1: 3,
			want:  7,
		},
		{
			name:  "x < alpha with negative values",
			alpha: 10,
			x:     -5,
			beta0: 11,
			beta1: 5,
			want:  11,
		},
		{
			name:  "x == alpha, should be beta1",
			alpha: 10,
			x:     10,
			beta0: 7,
			beta1: 3,
			want:  3,
		},
		{
			name:  "x > alpha, should be beta1",
			alpha: 10,
			x:     15,
			beta0: 7,
			beta1: 3,
			want:  3,
		},
		{
			name:  "x > alpha with negative alpha",
			alpha: -10,
			x:     15,
			beta0: 20,
			beta1: 8,
			want:  8,
		},
		{
			name:  "edge case: alpha = 0, x = 0",
			alpha: 0,
			x:     0,
			beta0: 5,
			beta1: 2,
			want:  2,
		},
		{
			name:  "edge case: alpha = 0, x > 0",
			alpha: 0,
			x:     1,
			beta0: 5,
			beta1: 2,
			want:  2,
		},
		{
			name:  "edge case: alpha = 0, x < 0",
			alpha: 0,
			x:     -1,
			beta0: 5,
			beta1: 2,
			want:  5,
		},
		{
			name:  "equal betas",
			alpha: 10,
			x:     5,
			beta0: 7,
			beta1: 7,
			want:  7,
		},
		{
			name:  "zero betas",
			alpha: 10,
			x:     5,
			beta0: 0,
			beta1: 0,
			want:  0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key0, key1, err := dcfScheme.GenerateDDCFKeys(n, tc.alpha, tc.beta0, tc.beta1)
			if err != nil {
				t.Fatalf("GenerateDDCFKeys failed: %v", err)
			}

			y0, err := dcfScheme.EvaluateDDCF(key0, tc.x)
			if err != nil {
				t.Fatalf("EvaluateDDCF for key0 failed: %v", err)
			}

			y1, err := dcfScheme.EvaluateDDCF(key1, tc.x)
			if err != nil {
				t.Fatalf("EvaluateDDCF for key1 failed: %v", err)
			}

			result := dcfScheme.Reconstruct(y0, y1)
			wantBigInt := big.NewInt(int64(tc.want))
			wantBigInt.Mod(wantBigInt, groupOrder)

			if result.Cmp(wantBigInt) != 0 {
				t.Errorf("y0(x) + y1(x) = %v, want %v", result, wantBigInt)
			}
		})
	}
}
