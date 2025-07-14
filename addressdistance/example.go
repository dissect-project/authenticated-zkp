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
type AddressDistanceCircuit struct {
	Lat1, Lon1 frontend.Variable `gnark:"address"`         // Private
	Lat2, Lon2 frontend.Variable `gnark:"current,public"`  // Public
	Distance   frontend.Variable `gnark:"distance,public"` // Public
	HashLat    frontend.Variable `gnark:"hash_lat,public"` // Public
	HashLon    frontend.Variable `gnark:"hash_lon,public"` // Public
}

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

func SignedInt64ToField(x int64, q *big.Int) *big.Int {
	val := big.NewInt(x)
	if x < 0 {
		val.Add(val, q) // ensure it's in the field (mod q)
	}
	return val
}

// Define defines the circuit's constraints
func (c *AddressDistanceCircuit) Define(api frontend.API) error {
	// deltaLat = Lat2 - Lat1
	deltaLat := api.Sub(c.Lat2, c.Lat1)
	// deltaLon = Lon2 - Lon1
	deltaLon := api.Sub(c.Lon2, c.Lon1)

	// squared distance = deltaLat^2 + deltaLon^2
	deltaLatSq := api.Mul(deltaLat, deltaLat)
	deltaLonSq := api.Mul(deltaLon, deltaLon)
	distSq := api.Add(deltaLatSq, deltaLonSq)

	// Define the threshold squared as a constant in the circuit
	// For example, threshold = 1000 meters, scaled by 1,000,000 => threshold scaled = 1000 * 1,000,000 = 1e9
	// But since we work on degrees * 1e6, you need to convert meters to degrees scaled by 1e6.
	// For simplicity here, we use a threshold in scaled degrees squared.
	// Let's say threshold = 0.01 degrees (approx ~1.11 km) scaled by 1e6 = 10,000
	// thresholdSq = 10,000^2 = 100,000,000

	scaledDist := api.Mul(c.Distance, 1000000) // Scale distance by 1e6
	thresholdSq := api.Mul(scaledDist, scaledDist)

	// Enforce distSq <= thresholdSq
	api.AssertIsLessOrEqual(distSq, thresholdSq)

	// Hash Lat using MiMC
	hFunc1, err := mimcCircuit.NewMiMC(api)
	if err != nil {
		return err
	}
	hFunc1.Write(c.Lat1)
	hash1 := hFunc1.Sum()

	// Assert that hash(Lat1) == HashLat
	api.AssertIsEqual(hash1, c.HashLat)

	// Hash Lat using MiMC
	hFunc2, err := mimcCircuit.NewMiMC(api)
	if err != nil {
		return err
	}
	hFunc2.Write(c.Lon1)
	hash2 := hFunc2.Sum()

	// Assert that hash(Lon1) == HashLon
	api.AssertIsEqual(hash2, c.HashLon)

	return nil
}

func main() {
	// Check if the correct number of arguments is provided
	if len(os.Args) != 2 {
		fmt.Println("Please provide exactly one argument")
		return
	}

	// Compile the circuit
	var circuit AddressDistanceCircuit
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

	// Scaling factor (e.g. 6 decimal places)
	scale := int64(1e6)
	q := ecc.BN254.ScalarField()

	// Input values
	// Latitude and Longitude
	lat1f, lon1f := 37.774900, -122.419400
	lat2f, lon2f := 37.775000, -123.419500

	// Convert to fixed-point signed integers
	lat1 := int64(lat1f * float64(scale))
	lon1 := int64(lon1f * float64(scale))
	lat2 := int64(lat2f * float64(scale))
	lon2 := int64(lon2f * float64(scale))

	// Set distance (in kms)
	Distance := int64(2)

	// Scale lat/lon by 1e6
	// Private inputs (Lat1, Lon1)
	Lat1 := SignedInt64ToField(lat1, q)
	Lon1 := SignedInt64ToField(lon1, q)
	// Public inputs (Lat2, Lon2)
	Lat2 := SignedInt64ToField(lat2, q)
	Lon2 := SignedInt64ToField(lon2, q)
	// Hash the Latitude using MiMC
	hashFunc1 := mimcNative.NewMiMC() // native hash
	hashFunc1.Write(Lat1.Bytes())
	hashOfLat := hashFunc1.Sum(nil)
	// Hash the Longitude using MiMC
	hashFunc2 := mimcNative.NewMiMC() // native hash
	hashFunc2.Write(Lon1.Bytes())
	hashOfLon := hashFunc2.Sum(nil)

	// Print variables
	fmt.Println("Latitude 1 (private):", Lat1)
	fmt.Println("Longitude 1 (private):", Lon1)
	fmt.Println("Latitude 2 (public):", Lat2)
	fmt.Println("Longitude 2 (public):", Lon2)
	fmt.Println("Hash of Latitude 1 (public):", new(big.Int).SetBytes(hashOfLat))
	fmt.Println("Hash of Longitude 1 (public):", new(big.Int).SetBytes(hashOfLon))

	// Create witness
	assignment := AddressDistanceCircuit{
		Lat1:     Lat1,
		Lon1:     Lon1,
		Lat2:     Lat2,
		Lon2:     Lon2,
		Distance: Distance,
		HashLat:  new(big.Int).SetBytes(hashOfLat),
		HashLon:  new(big.Int).SetBytes(hashOfLon),
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

	/*
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
			tamperedAssignment := AddressDistanceCircuit{
				Country:     []byte(CountryStr),
				HashCountry: new(big.Int).SetBytes(tamperedHashOfDOB),
			}

			witness, _ = frontend.NewWitness(&tamperedAssignment, ecc.BN254.ScalarField())
		} else {
			fmt.Println("No witness tampering requested.")
		}
	*/

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
