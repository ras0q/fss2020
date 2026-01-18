package fss2020

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

type DDCFKey struct {
	*DCFKey
	S *big.Int
}

func (d *DCFScheme) GenerateDDCFKeys(n int, alpha int, beta0 int, beta1 int) (*DDCFKey, *DDCFKey, error) {
	betaDiff := (beta0 - beta1) % int(d.groupOrder.Int64())
	key0, key1, err := d.GenerateKeys(n, alpha, betaDiff)
	if err != nil {
		return nil, nil, fmt.Errorf("generate dcf keys: %w", err)
	}

	b1 := big.NewInt(int64(beta1))
	s0, err := rand.Int(rand.Reader, d.groupOrder)
	if err != nil {
		return nil, nil, fmt.Errorf("random generation error: %w", err)
	}

	s1 := new(big.Int).Sub(b1, s0)
	s1.Mod(s1, d.groupOrder)

	ddcfKey0 := &DDCFKey{
		DCFKey: key0,
		S:      s0,
	}
	ddcfKey1 := &DDCFKey{
		DCFKey: key1,
		S:      s1,
	}

	return ddcfKey0, ddcfKey1, nil
}

func (d *DCFScheme) EvaluateDDCF(key *DDCFKey, x int) (*big.Int, error) {
	y, err := d.Evaluate(key.DCFKey, x)
	if err != nil {
		return nil, fmt.Errorf("evaluate ddcf: %w", err)
	}

	y.Add(y, key.S)
	y.Mod(y, d.groupOrder)

	return y, nil
}
