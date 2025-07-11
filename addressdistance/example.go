package main

import (
	"fmt"
	"math"
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

func haversine(lat1, lon1, lat2, lon2 float64) float64 {
	const R = 6371 // Earth radius in km
	phi1 := lat1 * math.Pi / 180
	phi2 := lat2 * math.Pi / 180
	deltaPhi := (lat2 - lat1) * math.Pi / 180
	deltaLambda := (lon2 - lon1) * math.Pi / 180

	a := math.Sin(deltaPhi/2)*math.Sin(deltaPhi/2) +
		math.Cos(phi1)*math.Cos(phi2)*math.Sin(deltaLambda/2)*math.Sin(deltaLambda/2)
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
	return R * c // distance in km
}

// Define defines the circuit's constraints
func (c *AddressDistanceCircuit) Define(api frontend.API) error {

	// Compute delta lat/lon
	dLat := api.Sub(c.Lat2, c.Lat1)
	dLon := api.Sub(c.Lon2, c.Lon1)

	// Compute squared distance (fixed point)
	dLat2 := api.Mul(dLat, dLat)
	dLon2 := api.Mul(dLon, dLon)

	sum := api.Add(dLat2, dLon2)
	// Check that the provided distance squared matches sum approximately
	distSquared := api.Mul(c.Distance, c.Distance)
	// Allow some small error margin (epsilon)
	epsilon := frontend.Variable(10) // adjust as needed

	// Enforce |distSquared - sum| <= epsilon
	diff := api.Sub(distSquared, sum)
	diffNeg := api.Neg(diff)

	api.Println("Distance squared:", distSquared)
	api.Println("Sum of squares:", sum)

	api.AssertIsLessOrEqual(diff, epsilon)
	api.AssertIsLessOrEqual(diffNeg, epsilon)

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

	// Input values
	// Latitude and Longitude of the first address (private)
	Lat1 := "38.7223" // Latitude of Lisbon, Portugal
	Lon1 := "-9.1393" // Longitude of Lisbon, Portugal
	// Latitude and Longitude of the second address (public)
	Lat2 := "41.1496" // Latitude of Porto, Portugal
	Lon2 := "-8.6109" // Longitude of Porto, Portugal
	// Hash the Latitude using MiMC
	hashFunc1 := mimcNative.NewMiMC() // native hash
	hashFunc1.Write([]byte(Lat1))
	hashOfLat := hashFunc1.Sum(nil)
	// Hash the Longitude using MiMC
	hashFunc2 := mimcNative.NewMiMC() // native hash
	hashFunc2.Write([]byte(Lon1))
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
		Lat1:     new(big.Int).SetBytes([]byte(Lat1)),
		Lon1:     new(big.Int).SetBytes([]byte(Lon1)),
		Lat2:     new(big.Int).SetBytes([]byte(Lat2)),
		Lon2:     new(big.Int).SetBytes([]byte(Lon2)),
		Distance: 100,
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
