package main

import (
	"fmt"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	mimcNative "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend/plonk"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	mimcCircuit "github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/test/unsafekzg"
)

// Circuit definition (Checks if A < B and verifies hash of A)
type OverAgeVerifyCircuit struct {
	DOB     frontend.Variable `gnark:"dob"`             // Private
	Today   frontend.Variable `gnark:",public"`         // Public
	MinAge  frontend.Variable `gnark:",public"`         // Public
	HashAge frontend.Variable `gnark:"hash_dob,public"` // Public
}

// Define defines the circuit's constraints
func (c *OverAgeVerifyCircuit) Define(api frontend.API) error {

	// Convert MinAge from years to days (assuming 1 year = 365 days)
	minAgeInDays := api.Mul(c.MinAge, 10000)
	// Calculate the minimum DOB by subtracting minAgeInDays from Today
	minDOB := api.Sub(c.Today, minAgeInDays)
	// Assert that DOB is less than or equal to minDOB (ensuring age >= MinAge)
	api.AssertIsLessOrEqual(c.DOB, minDOB)

	// Hash DOB using MiMC
	hFunc, err := mimcCircuit.NewMiMC(api)
	if err != nil {
		return err
	}
	hFunc.Write(c.DOB)
	hash := hFunc.Sum()

	// Assert that hash(A) == HashA
	api.AssertIsEqual(hash, c.HashAge)

	return nil
}

func main() {
	// Input values
	// Minimum age in years
	minAge := big.NewInt(18) // This is a public variable
	// Birth date in YYYYMMDD format
	birthDateStr := "19990816"
	DOB := new(big.Int)
	DOB.SetString(birthDateStr, 10) // base 10
	// Today's date in YYYYMMDD format
	todayDateStr := "20250529"
	Today := new(big.Int)
	Today.SetString(todayDateStr, 10) // base 10
	// Hash the birth date using MiMC
	hashFunc := mimcNative.NewMiMC() // native hash
	hashFunc.Write(DOB.Bytes())
	hashOfA := hashFunc.Sum(nil)

	// Print variables
	fmt.Println("DOB (private):", DOB)
	fmt.Println("TODAY (public):", Today)
	fmt.Println("Hash of DOB (public):", new(big.Int).SetBytes(hashOfA))

	// Change value of DOB
	//newBirthDateStr := "19980816"
	//DOB = new(big.Int)
	//DOB.SetString(newBirthDateStr, 10) // base 10

	// Compile the circuit
	var circuit OverAgeVerifyCircuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}

	// Create witness
	assignment := OverAgeVerifyCircuit{
		DOB:     DOB,
		Today:   Today,
		MinAge:  minAge,
		HashAge: new(big.Int).SetBytes(hashOfA),
	}

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}

	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}

	// Setup
	scs := ccs.(*cs.SparseR1CS)
	srs, srsLagrange, err := unsafekzg.NewSRS(scs)
	if err != nil {
		panic(err)
	}
	pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
	if err != nil {
		panic(err)
	}

	// Prove
	proof, err := plonk.Prove(ccs, pk, witness)
	if err != nil {
		fmt.Println("❌ Proof generation failed! Likely a constraint was not satisfied.")
		fmt.Println("Error details:", err)
		os.Exit(1)
	} else {
		fmt.Println("✅ Proof generated successfully!")
	}

	// Verify
	err = plonk.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Println("❌ Proof failed:", err)
		os.Exit(1)
	} else {
		fmt.Println("✅ Proof verified successfully!")
	}

	// Extract and print all public variables
	fmt.Println("Public witness values:", publicWitness.Vector())
}
