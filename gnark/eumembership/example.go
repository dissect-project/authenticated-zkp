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

// Circuit definition (Checks if Country is a member of the EU)
type EUCountryMembershipCircuit struct {
	Country     frontend.Variable `gnark:"country"`             // Private
	HashCountry frontend.Variable `gnark:"hash_country,public"` // Public
}

// Define defines the circuit's constraints
func (c *EUCountryMembershipCircuit) Define(api frontend.API) error {

	// List of the 27 EU member countries
	members := []frontend.Variable{
		[]byte("Austria"),
		[]byte("Belgium"),
		[]byte("Bulgaria"),
		[]byte("Croatia"),
		[]byte("Cyprus"),
		[]byte("Czechia"),
		[]byte("Denmark"),
		[]byte("Estonia"),
		[]byte("Finland"),
		[]byte("France"),
		[]byte("Germany"),
		[]byte("Greece"),
		[]byte("Hungary"),
		[]byte("Ireland"),
		[]byte("Italy"),
		[]byte("Latvia"),
		[]byte("Lithuania"),
		[]byte("Luxembourg"),
		[]byte("Malta"),
		[]byte("Netherlands"),
		[]byte("Poland"),
		[]byte("Portugal"),
		[]byte("Romania"),
		[]byte("Slovakia"),
		[]byte("Slovenia"),
		[]byte("Spain"),
		[]byte("Sweden"),
	}

	// Initialize a match variable to 0
	match := frontend.Variable(0)
	// Iterate over the member countries
	for _, v := range members {
		// Check if the input country matches the member country
		isZero := api.IsZero(api.Sub(c.Country, v))
		match = api.Add(match, isZero)
	}
	// Assert that match is 1 (meaning the country is in the list)
	api.AssertIsEqual(match, 1)

	// Hash Country using MiMC
	hFunc, err := mimcCircuit.NewMiMC(api)
	if err != nil {
		return err
	}
	hFunc.Write(c.Country)
	hash := hFunc.Sum()

	// Assert that hash(Country) == HashCountry
	api.AssertIsEqual(hash, c.HashCountry)

	return nil
}

func main() {
	// Check if the correct number of arguments is provided
	if len(os.Args) != 2 {
		fmt.Println("Please provide exactly one argument")
		return
	}

	// Compile the circuit
	var circuit EUCountryMembershipCircuit
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
	// Country
	CountryStr := "Portugal"
	// Hash the country using MiMC
	hashFunc := mimcNative.NewMiMC() // native hash
	hashFunc.Write([]byte(CountryStr))
	hashOfCountry := hashFunc.Sum(nil)

	// Print variables
	fmt.Println("Country (private):", CountryStr)
	fmt.Println("Hash of Country (public):", new(big.Int).SetBytes(hashOfCountry))

	// Create witness
	assignment := EUCountryMembershipCircuit{
		Country:     []byte(CountryStr),
		HashCountry: new(big.Int).SetBytes(hashOfCountry),
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
		// Simulate the tampering of Country's hash
		CountryStr := "Spain"

		tamperedHashFunc := mimcNative.NewMiMC() // native hash
		tamperedHashFunc.Write([]byte(CountryStr))
		tamperedHashOfDOB := tamperedHashFunc.Sum(nil)

		// Create a new witness with the tampered value
		// Create witness
		tamperedAssignment := EUCountryMembershipCircuit{
			Country:     []byte(CountryStr),
			HashCountry: new(big.Int).SetBytes(tamperedHashOfDOB),
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
