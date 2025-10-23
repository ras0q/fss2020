// This package is a Go implementation of the Function Secret Sharing (FSS) scheme described in
// E. Boyle et al., “Function Secret Sharing for Mixed-Mode and Fixed-Point Secure Computation,” Cryptology ePrint Archive, 2020.
// Link: https://eprint.iacr.org/2020/1392
package fss2020

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"math/big"
)

// NOTE: limited to 2 parties for now
const partyNum = 2
const (
	left  = 0
	right = 1
)

type DCFScheme struct {
	lambdaInBits int
	groupOrder   *big.Int
}

func NewDCFScheme(lambdaInBits int, groupOrder *big.Int) *DCFScheme {
	return &DCFScheme{
		lambdaInBits,
		groupOrder,
	}
}

func (d *DCFScheme) GenerateKeys(n int, alpha int, beta int) (key0 *DCFKey, key1 *DCFKey, err error) {
	threshold := 1 << (n - 1)
	if alpha >= threshold || alpha < -threshold {
		return nil, nil, fmt.Errorf("alpha (%d) must be within the range [-2^{n-1} (%d), 2^{n-1} (%d) - 1]", alpha, -threshold, threshold-1)
	}

	// Map α from [-2^{n-1}, 2^{n-1} - 1] to [0, 2^n - 1]
	alpha += threshold

	seeds := make([][][]byte, partyNum)
	for i := range seeds {
		seeds[i] = make([][]byte, n+1)

		initialSeed := make([]byte, d.lambdaInBits/8)
		if _, err := rand.Read(initialSeed); err != nil {
			return nil, nil, fmt.Errorf("random generation error: %w", err)
		}

		seeds[i][0] = initialSeed
	}

	valueAlpha := new(big.Int)

	ts := make([][]byte, partyNum)
	for i := range ts {
		ts[i] = make([]byte, n+1)
		ts[i][0] = byte(i)
	}

	correctionWords := make([]*DCFCorrectionWord, n)

	for i := range n {
		alphaBit := (alpha >> (n - i - 1)) & 1

		isPartyActive := [partyNum]bool{
			ts[0][i] == 1,
			ts[1][i] == 1,
		}

		nodes := [partyNum]*ExpandedDCFNode{}
		for party := range partyNum {
			// s_{b,L} || v_{b,L} || t_{b,L} || s_{b,R} || v_{b,R} || t_{b,R} ← PRG(s_{b}[i])
			node, err := d.expandDCFNode(seeds[party][i])
			if err != nil {
				return nil, nil, fmt.Errorf("expand dcf node: %w", err)
			}

			nodes[party] = node
		}

		keep, lose := right, left
		if alphaBit == 0 {
			keep, lose = left, right
		}

		// s_{CW} = s_{0,Lose} ⊕ s_{1,Lose}
		seedCW := make([]byte, d.lambdaInBits/8)
		for j := range seedCW {
			seedCW[j] = nodes[0].Seeds[lose][j] ^ nodes[1].Seeds[lose][j]
		}

		// v_{CW} = (-1)^{t_{1}[i]} * [Convert(v_{1,Lose}) - Convert(v_{0,Lose}) - V_α]
		v0LoseConverted, err := d.mapToGroupElement(nodes[0].Values[lose])
		if err != nil {
			return nil, nil, fmt.Errorf("convert value: %w", err)
		}

		v1LoseConverted, err := d.mapToGroupElement(nodes[1].Values[lose])
		if err != nil {
			return nil, nil, fmt.Errorf("convert value: %w", err)
		}

		valueCW := new(big.Int)
		valueCW.Sub(v1LoseConverted, v0LoseConverted)
		valueCW.Sub(valueCW, valueAlpha)

		if isPartyActive[1] {
			valueCW.Neg(valueCW)
		}

		// if Lose == L:
		// V_{CW} = V_{CW} + (-1)^{t_{1}[i]} * β
		if lose == left {
			betaCorrected := new(big.Int).SetInt64(int64(beta))
			if isPartyActive[1] {
				betaCorrected.Neg(betaCorrected)
			}

			valueCW.Add(valueCW, betaCorrected)
		}

		// V_α = V_α - Convert(v_{1,Keep}) + Convert(v_{0,Keep}) + (-1)^{t_{1}[i]} * V_{CW}
		v0KeepConverted, err := d.mapToGroupElement(nodes[0].Values[keep])
		if err != nil {
			return nil, nil, fmt.Errorf("convert value: %w", err)
		}

		v1KeepConverted, err := d.mapToGroupElement(nodes[1].Values[keep])
		if err != nil {
			return nil, nil, fmt.Errorf("convert value: %w", err)
		}

		valueAlpha.Sub(valueAlpha, v1KeepConverted)
		valueAlpha.Add(valueAlpha, v0KeepConverted)

		valueCWCorrected := new(big.Int).Set(valueCW)
		if isPartyActive[1] {
			valueCWCorrected.Neg(valueCWCorrected)
		}

		valueAlpha.Add(valueAlpha, valueCWCorrected)

		// t_{CW}[L] = t_{0,L} ⊕ t_{1,L} ⊕ α_i ⊕ 1
		// t_{CW}[R] = t_{0,R} ⊕ t_{1,R} ⊕ α_i
		tCWs := [2]byte{}
		tCWs[left] = nodes[0].TBits[left] ^ nodes[1].TBits[left] ^ byte(alphaBit) ^ 1
		tCWs[right] = nodes[0].TBits[right] ^ nodes[1].TBits[right] ^ byte(alphaBit)

		// CW[i] = s_{CW} || v_{CW} || t_{CW}[L] || t_{CW}[R]
		correctionWords[i] = &DCFCorrectionWord{
			Seed:  seedCW,
			Value: valueCW,
			TBits: [2]byte{tCWs[left], tCWs[right]},
		}

		// s_{b}[i] = s_{b}[Keep] ⊕ t{b}[i] * s_{CW} for b ∈ {0, 1}
		for party := range partyNum {
			seeds[party][i+1] = make([]byte, d.lambdaInBits/8)
			for j := range seeds[party][i+1] {
				seeds[party][i+1][j] = nodes[party].Seeds[keep][j]
				if isPartyActive[party] {
					seeds[party][i+1][j] ^= seedCW[j]
				}
			}
		}

		// t_{i+1} = t_{b}[Keep] ⊕ t_{b}[i] * t_{CW}[Keep] for b ∈ {0, 1}
		for party := range partyNum {
			ts[party][i+1] = nodes[party].TBits[keep]
			if isPartyActive[party] {
				ts[party][i+1] ^= tCWs[keep]
			}
		}
	}

	// final correction value
	// CW[n] = (-1)^{t_{1}[n]} * [Convert(s_{1}[n]) - Convert(s_{0}[n]) - V_α]
	s0nConverted, err := d.mapToGroupElement(seeds[0][n])
	if err != nil {
		return nil, nil, fmt.Errorf("convert value: %w", err)
	}

	s1nConverted, err := d.mapToGroupElement(seeds[1][n])
	if err != nil {
		return nil, nil, fmt.Errorf("convert value: %w", err)
	}

	isParty1Active := ts[1][n] == 1

	valueCW := new(big.Int)
	valueCW.Sub(s1nConverted, s0nConverted)
	valueCW.Sub(valueCW, valueAlpha)

	if isParty1Active {
		valueCW.Neg(valueCW)
	}

	// key_b = s_b[0] || CW[0] || ... || CW[n] for b ∈ {0, 1}
	key0 = &DCFKey{
		Party:      0,
		Seed:       seeds[0][0],
		CWs:        correctionWords,
		FinalValue: new(big.Int).Set(valueCW),
	}

	correctionWordsForParty1 := make([]*DCFCorrectionWord, n)
	for i, cw := range correctionWords {
		correctionWordsForParty1[i] = &DCFCorrectionWord{
			Seed:  append([]byte(nil), cw.Seed...),
			Value: new(big.Int).Set(cw.Value),
			TBits: cw.TBits,
		}
	}

	key1 = &DCFKey{
		Party:      1,
		Seed:       seeds[1][0],
		CWs:        correctionWordsForParty1,
		FinalValue: new(big.Int).Set(valueCW),
	}

	return key0, key1, nil
}

func (d *DCFScheme) Evaluate(key *DCFKey, x int) (*big.Int, error) {
	n := len(key.CWs)

	threshold := 1 << (n - 1)
	if x >= threshold || x < -threshold {
		return nil, fmt.Errorf("x (%d) must be within the range [-2^{n-1} (%d), 2^{n-1} (%d) - 1]", x, -threshold, threshold-1)
	}

	// Map x from [-2^{n-1}, 2^{n-1} - 1] to [0, 2^n - 1]
	x += threshold

	tbits := make([]byte, n+1)
	tbits[0] = byte(key.Party)
	value := big.NewInt(0)
	seeds := make([][]byte, n+1)
	seeds[0] = key.Seed

	for i := range n {
		// s_{^,L} || v_{^,L} || t_{^,L} || s_{^,R} || v_{^,R} || t_{^,R} ← PRG(s[i])
		node, err := d.expandDCFNode(seeds[i])
		if err != nil {
			return nil, fmt.Errorf("expand dcf node: %w", err)
		}

		// τ[i] = (s_{^,L} || t_{^,L} || s_{^,R} || t_{^,R}) ⊕ (t[i] * [s_{CW} || t_{CW}[L] || s_{CW} || t_{CW}[R}])
		sL := make([]byte, len(node.Seeds[left]))
		copy(sL, node.Seeds[left])
		sR := make([]byte, len(node.Seeds[right]))
		copy(sR, node.Seeds[right])
		tL, tR := node.TBits[left], node.TBits[right]

		if tbits[i] == 1 {
			for j := range d.lambdaInBits / 8 {
				sL[j] ^= key.CWs[i].Seed[j]
				sR[j] ^= key.CWs[i].Seed[j]
			}

			tL ^= key.CWs[i].TBits[left]
			tR ^= key.CWs[i].TBits[right]
		}

		xi := (x >> (n - i - 1)) & 1

		if xi == 0 {
			// V = V + (-1)^b * [Convert(v_{^,L}) + t[i] * V_{CW}]
			vConverted, err := d.mapToGroupElement(node.Values[0])
			if err != nil {
				return nil, fmt.Errorf("convert value: %w", err)
			}

			if tbits[i] == 1 {
				vConverted.Add(vConverted, key.CWs[i].Value)
			}

			if key.Party%2 == 1 {
				vConverted.Neg(vConverted)
			}

			value.Add(value, vConverted)

			// s[i+1] = s_L
			seeds[i+1] = sL
			// t[i+1] = t_L
			tbits[i+1] = tL
		} else {
			// V = V + (-1)^b * [Convert(v_{^,R}) + t[i] * V_{CW}]
			vConverted, err := d.mapToGroupElement(node.Values[1])
			if err != nil {
				return nil, fmt.Errorf("convert value: %w", err)
			}

			if tbits[i] == 1 {
				vConverted.Add(vConverted, key.CWs[i].Value)
			}

			if key.Party%2 == 1 {
				vConverted.Neg(vConverted)
			}

			value.Add(value, vConverted)
			value.Mod(value, d.groupOrder)

			// s[i+1] = s_R
			seeds[i+1] = sR
			// t[i+1] = t_R
			tbits[i+1] = tR
		}
	}

	// V = V + (-1)^b * [Convert(s[n]) + t[n] * CW[n]]
	snConverted, err := d.mapToGroupElement(seeds[n])
	if err != nil {
		return nil, fmt.Errorf("convert value: %w", err)
	}

	if tbits[n] == 1 {
		snConverted.Add(snConverted, key.FinalValue)
	}

	if key.Party%2 == 1 {
		snConverted.Neg(snConverted)
	}

	value.Add(value, snConverted)
	value.Mod(value, d.groupOrder)

	return value, nil
}

func (d *DCFScheme) Reconstruct(ys ...*big.Int) *big.Int {
	result := new(big.Int)
	for _, y := range ys {
		result.Add(result, y)
		result.Mod(result, d.groupOrder)
	}

	return result
}

type ExpandedDCFNode struct {
	Seeds  [2][]byte
	Values [2][]byte
	TBits  [2]byte
}

// G: {0,1}^λ → {0,1}^{2(2λ+1)}  (λ = security parameter)
// s_{b,L} || v_{b,L} || t_{b,L} || s_{b,R} || v_{b,R} || t_{b,R} ← PRG(seed)
func (d *DCFScheme) expandDCFNode(seed []byte) (*ExpandedDCFNode, error) {
	lambdaInBytes := d.lambdaInBits / 8
	if len(seed) != lambdaInBytes {
		return nil, fmt.Errorf("seed length must be equal to security parameter: (%d != %d)", len(seed), lambdaInBytes)
	}

	block, err := aes.NewCipher(seed)
	if err != nil {
		return nil, fmt.Errorf("aes cipher creation error: %w", err)
	}

	iv := make([]byte, aes.BlockSize)
	stream := cipher.NewCTR(block, iv)

	outputSize := (lambdaInBytes*2 + 1) * 2
	output := make([]byte, outputSize)
	stream.XORKeyStream(output, output)

	// output layout:
	// 0      λ     2λ    2λ+1   3λ+1   4λ+1   4λ+2
	// |--sL--|--vL--|--tL--|--sR--|--vR--|--tR--|
	node := &ExpandedDCFNode{
		Seeds: [2][]byte{
			output[0:lambdaInBytes],
			output[2*lambdaInBytes+1 : 3*lambdaInBytes+1],
		},
		Values: [2][]byte{
			output[lambdaInBytes : 2*lambdaInBytes],
			output[3*lambdaInBytes+1 : 4*lambdaInBytes+1],
		},
		TBits: [2]byte{
			output[2*lambdaInBytes] & 1,
			output[4*lambdaInBytes+1] & 1,
		},
	}

	return node, nil
}

// Convert_𝔾: {0,1}^λ → 𝔾
func (d DCFScheme) mapToGroupElement(input []byte) (*big.Int, error) {
	if len(input) != int(d.lambdaInBits/8) {
		return nil, fmt.Errorf("value length must be equal to security parameter (%d != %d)", len(input), d.lambdaInBits/8)
	}

	if !isPowerOfTwo(d.groupOrder) {
		return nil, fmt.Errorf("unsupported group order: must be a power of two")
	}

	k := d.groupOrder.BitLen() - 1
	if k > d.lambdaInBits {
		return nil, fmt.Errorf("unsupported group order: bit length must be less than or equal to security parameter (%d > %d)", k, d.lambdaInBits)
	}

	// simply outputs the first k bits of the input
	requiredBytes := (k + 7) / 8
	if requiredBytes > len(input) {
		return nil, fmt.Errorf("internal error: required bytes exceed input length (%d > %d)", requiredBytes, len(input))
	}

	output := new(big.Int).SetBytes(input[:requiredBytes])
	bitsToShift := uint(requiredBytes*8 - k) //nolint: gosec
	output.Rsh(output, bitsToShift)

	return output, nil
}

func isPowerOfTwo(n *big.Int) bool {
	if n.Sign() <= 0 {
		return false
	}

	nMinus1 := new(big.Int).Sub(n, big.NewInt(1))

	return new(big.Int).And(n, nMinus1).Cmp(big.NewInt(0)) == 0
}

type DCFKey struct {
	Party      int
	Seed       []byte
	CWs        []*DCFCorrectionWord
	FinalValue *big.Int
}

type DCFCorrectionWord struct {
	Seed  []byte
	Value *big.Int
	TBits [2]byte
}
