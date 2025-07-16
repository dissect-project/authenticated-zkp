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
type CompareAndVerifyCircuit struct {
	A     frontend.Variable `gnark:"a"`             // Private
	B     frontend.Variable `gnark:",public"`       // Public
	HashA frontend.Variable `gnark:"hash_a,public"` // Public
}

// Define defines the circuit's constraints
func (c *CompareAndVerifyCircuit) Define(api frontend.API) error {
	// Assert that B > A
	api.AssertIsLessOrEqual(c.A, c.B)

	// Hash A using MiMC
	hFunc, err := mimcCircuit.NewMiMC(api)
	if err != nil {
		return err
	}
	hFunc.Write(c.A)
	hash := hFunc.Sum()

	// Assert that hash(A) == HashA
	api.AssertIsEqual(hash, c.HashA)

	return nil
}

func main() {
	// Check if the correct number of arguments is provided
	if len(os.Args) != 2 {
		fmt.Println("Please provide exactly one argument")
		return
	}

	// Compile the circuit
	var circuit CompareAndVerifyCircuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
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
	//fmt.Printf("vk: %d, %d\n", vk, unsafe.Sizeof(vk))

	// Input values
	A := big.NewInt(25) // private
	B := big.NewInt(40) // public

	hashFunc := mimcNative.NewMiMC() // native hash
	hashFunc.Write(A.Bytes())
	hashOfA := hashFunc.Sum(nil)

	// Print variables
	fmt.Println("A (private):", A)
	fmt.Println("B (public):", B)
	fmt.Println("Hash of A (public):", new(big.Int).SetBytes(hashOfA))

	// Create witness
	assignment := CompareAndVerifyCircuit{
		A:     A,
		B:     B,
		HashA: new(big.Int).SetBytes(hashOfA),
	}

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
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

	// Get the tamper argument from command line
	arg := os.Args[1]

	// Check if the argument is "tamper"
	if arg == "tamper" {
		fmt.Println("Executing tampering of witness...")
		// Simulate the tampering of A's hash
		tamperedA := big.NewInt(35)

		tamperedHashFunc := mimcNative.NewMiMC() // native hash
		tamperedHashFunc.Write(tamperedA.Bytes())
		tamperedHashOfA := tamperedHashFunc.Sum(nil)

		// Create a new witness with the tampered value
		tamperedAssignment := CompareAndVerifyCircuit{
			A:     A,
			B:     B,
			HashA: new(big.Int).SetBytes(tamperedHashOfA),
		}

		witness, _ = frontend.NewWitness(&tamperedAssignment, ecc.BN254.ScalarField())
	} else {
		fmt.Println("No witness tampering requested.")
	}

	// Create public witness (only public inputs)
	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
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
