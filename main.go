package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

const MILLERRABIN_ITER_NUM = 64

// GenerateRandomNumber generates a random big.Int with a specified bit length
// The number is uniformly distributed in [2^(bits-1), 2^bits)
// This funcitons deals with big.Int since it is can store extremely large numbers which is usually the case with crypto applications
// big.Int is returned as a pointer for effcency and because it's functions require it as a pointer
func GenerateRandomOddNumber(bits int) (*big.Int, error) {
	// This sets the upper bound of generaion. This is achieved by shifting left the binary represntation of number one by the amount of bits for example if the bits were 3 0001 = 1 would be 1000 = 8 or 2^3
	max := new(big.Int).Lsh(big.NewInt(1), uint(bits))
	// Set the lower bound: 2^(bits-1)
	min := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))

	// Calculate the range size: max - min
	rangeSize := new(big.Int).Sub(max, min)

	// What makes this random selecion cryptographically secure is that rand.Reader interacts with the OS random number generator that collects entropy from around the system
	// The critical issue here is that this generates numbers from 0 to RangeSize
	randomNumber, err := rand.Int(rand.Reader, rangeSize)

	if err != nil {
		return nil, err
	}

	// To make sure that the number isnt trivially small min is added to the randomNumber
	// This works because the smallest possible value is 0 + min = min
	// The largest possible value is (rangeSize-1) + min = (max - min - 1) + min = max - 1 which is still within our bounds
	randomNumber.Add(randomNumber, min)

	// Sets the LSB to 1 to ensure it is an odd number. This is achieved by a simple or operation with 1
	randomNumber.Or(randomNumber, big.NewInt(1))

	return randomNumber, nil
}

// This is a test that does iterations rounds over a number n to determine the probability of it being a prime or not
// https://youtu.be/8i0UnX7Snkc this video explains it very well
func MillerRabinPrimalityTest(n *big.Int) bool {
	// This handles the simple static cases
	if n.Cmp(big.NewInt(2)) == 0 {
		return true // 2 is a prime number
	}

	if n.Cmp(big.NewInt(1)) <= 0 || n.Bit(0) == 0 {
		return false // n <= 1 or even numbers are not prime and 2 is handled above
	}

	// Decompose n -1 into 2^k * m
	m := new(big.Int).Sub(n, big.NewInt(1)) // sets m = n -1
	k := 0

	// Stop when it is odd aka cant be divided by two anymore
	for m.Bit(0) == 0 {
		m.Rsh(m, 1) // This is an effecient way to divide 2 by just shifting the bits
		k++
	}

	// Perform Miller-Rabin test for 'iterations' rounds
	for i := 0; i < MILLERRABIN_ITER_NUM; i++ {
		// Base a must be greater than 1 or less than n-1 otherwise the test is trivial
		// Generate a random base a in the range [2, n-2]
		a, err := rand.Int(rand.Reader, new(big.Int).Sub(n, big.NewInt(4))) // Range: [0, n-4] -4 because we later add -2 to ensure it is in the minimum bounds
		if err != nil {
			return false
		}
		a.Add(a, big.NewInt(2)) // Shift to [2, n-2]

		// Compute b = a^m % n
		b := new(big.Int).Exp(a, m, n)

		// Check if b == 1 or b == n-1
		if b.Cmp(big.NewInt(1)) == 0 || b.Cmp(new(big.Int).Sub(n, big.NewInt(1))) == 0 {
			continue // Passes this iteration
		}

		// Perform repeated squaring
		composite := true
		for j := 0; j < k-1; j++ {
			b.Exp(b, big.NewInt(2), n) // b = b^2 % n

			// Check if b == n-1
			if b.Cmp(new(big.Int).Sub(n, big.NewInt(1))) == 0 {
				composite = false
				break
			}
		}

		// If composite is still true, n is not prime
		if composite {
			return false
		}
	}
	// If all iterations passed, n is likely prime
	return true
}

// This function simply generates the
func GeneratePrime(bits int) (*big.Int, error) {
	for {
		// Generate a random odd number
		candidate, err := GenerateRandomOddNumber(bits)
		if err != nil {
			return nil, err
		}

		// Test primality using Miller-Rabin
		if MillerRabinPrimalityTest(candidate) {
			return candidate, nil // Return the prime number
		}
	}
}

func GenerateTwoPrimes(bits int) (*big.Int, *big.Int, error) {
	// Generate the first prime
	p, err := GeneratePrime(bits)
	if err != nil {
		return nil, nil, err
	}

	var q *big.Int
	for {
		// Generate the second prime
		q, err = GeneratePrime(bits)
		if err != nil {
			return nil, nil, err
		}

		// Ensure p and q are distinct
		if p.Cmp(q) != 0 {
			break
		}
	}

	return p, q, nil
}

func main() {
	p, q, _ := GenerateTwoPrimes(1024)
	fmt.Println(p)
	fmt.Println()
	fmt.Println(q)
}
