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

// Circuit definition (Checks if a person is habilitated to drive a given type of vehicle in the EU)
type DrivingLicenseHabilitationCircuit struct {
	Habilitation     frontend.Variable `gnark:"habilitation"`             // Private
	Category         frontend.Variable `gnark:",public"`                  // Public
	HashHabilitation frontend.Variable `gnark:"hash_habilitation,public"` // Public
}

// Define defines the circuit's constraints
func (c *DrivingLicenseHabilitationCircuit) Define(api frontend.API) error {
	const len = 17
	var isPresent frontend.Variable = 0

	// Get index
	index := api.Sub(len, api.Add(c.Category, 1))
	//Get the binary representation of Habilitation
	binHabilitations := api.ToBinary(c.Habilitation, len)
	// Iterate over the habilitations
	for i := 0; i < len; i++ {
		// Check if the index is equal to the given index
		isIndex := api.Cmp(index, i)
		// Check if the index matches
		isZero := api.IsZero(isIndex)
		// Add the value at the index to the auxiliary variable isPresent
		isPresent = api.Add(isPresent, api.Select(isZero, binHabilitations[i], 0))
	}

	// Assert that the category is set to 1
	api.AssertIsEqual(isPresent, 1)

	// Hash Habilitation using MiMC
	hFunc, err := mimcCircuit.NewMiMC(api)
	if err != nil {
		return err
	}
	hFunc.Write(c.Habilitation)
	hash := hFunc.Sum()

	// Assert that hash(Habilitation) == HashHabilitation
	api.AssertIsEqual(hash, c.HashHabilitation)

	return nil
}

func binaryStringToBigInt(binStr string) *big.Int {
	n := new(big.Int)
	for i := 0; i < len(binStr); i++ {
		bit := binStr[len(binStr)-1-i] // reverse index for LSB
		if bit == '1' {
			n.Add(n, new(big.Int).Lsh(big.NewInt(1), uint(i))) // n += 2^i
		}
	}
	return n
}

func main() {
	// Check if the correct number of arguments is provided
	if len(os.Args) != 2 {
		fmt.Println("Please provide exactly one argument")
		return
	}

	// Compile the circuit
	var circuit DrivingLicenseHabilitationCircuit
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

	// Input values
	// Category of the driving license (e.g. "1" for A1)
	Category := 2 // Represents the index on the Habilitation string (0-based index)
	// Habilitations (AM A1 A2 A B1 B C1 C D1 D BE C1E CE D1E DE L  T)
	// Index values:  0  1  2  3 4  5 6  7 8  9 10 11  12 13  14 15 16
	Habilitation := "11101100000000000"
	HabilitationInt := binaryStringToBigInt(Habilitation)
	// Hash the habilitations using MiMC
	hashFunc := mimcNative.NewMiMC()
	hashFunc.Write(HabilitationInt.Bytes())
	hashOfHabilitation := hashFunc.Sum(nil)

	// Print variables
	fmt.Println("Habilitations (private):", Habilitation)
	fmt.Println("Hash of Habilitations (public):", new(big.Int).SetBytes(hashOfHabilitation))

	// Create witness
	assignment := DrivingLicenseHabilitationCircuit{
		Habilitation:     HabilitationInt,
		Category:         Category,
		HashHabilitation: new(big.Int).SetBytes(hashOfHabilitation),
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
		// Simulate the tampering of Habilitation's hash
		Habilitation := "11111100000000000"
		HabilitationInt := binaryStringToBigInt(Habilitation)
		// Hash the habilitations using MiMC
		tamperedHashFunc := mimcNative.NewMiMC() // native hash
		tamperedHashFunc.Write(HabilitationInt.Bytes())
		tamperedHashOfHabilitation := tamperedHashFunc.Sum(nil)

		// Create a new witness with the tampered value
		// Create witness
		tamperedAssignment := DrivingLicenseHabilitationCircuit{
			Habilitation:     HabilitationInt,
			Category:         Category,
			HashHabilitation: new(big.Int).SetBytes(tamperedHashOfHabilitation),
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
