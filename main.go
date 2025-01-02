package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"os"
)

const (
	MILLERRABIN_ITER_NUM = 64
	PUBLIC_EXPONENT      = 65537
	BITS                 = 2048
)

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

func CalculateRSAComponents(p, q *big.Int) (*big.Int, *big.Int) {
	// Calculate n = p * q
	n := new(big.Int).Mul(p, q)

	// Calculate phi(n) = (p-1) * (q-1)
	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
	qMinus1 := new(big.Int).Sub(q, big.NewInt(1))
	phi := new(big.Int).Mul(pMinus1, qMinus1)

	return n, phi
}

func GenerateRSAKeys(bits int) (*big.Int, *big.Int, *big.Int, *big.Int, error) {
	// Generate two distinct primes
	p, q, err := GenerateTwoPrimes(bits / 2) // Divide bits evenly between p and q
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Calculate n and phi(n)
	n, phi := CalculateRSAComponents(p, q)

	// Define the public exponent e
	e := big.NewInt(PUBLIC_EXPONENT)

	// Calculate the private exponent d
	d := new(big.Int).ModInverse(e, phi)
	if d == nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to compute modular inverse for d")
	}

	return n, e, d, phi, nil
}

// Save RSA public key
func SavePublicKey(filename string, n, e *big.Int) error {
	// Serialize the public key
	pubKey := fmt.Sprintf("%s\n%s\n%s\n",
		"-----BEGIN RSA PUBLIC KEY-----",
		base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("n:%s\ne:%s", n.String(), e.String()))),
		"-----END RSA PUBLIC KEY-----",
	)

	// Write to file
	return os.WriteFile(filename, []byte(pubKey), 0600)
}

// Save RSA private key
func SavePrivateKey(filename string, n, d *big.Int) error {
	// Serialize the private key
	privKey := fmt.Sprintf("%s\n%s\n%s\n",
		"-----BEGIN RSA PRIVATE KEY-----",
		base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("n:%s\nd:%s", n.String(), d.String()))),
		"-----END RSA PRIVATE KEY-----",
	)

	// Write to file
	return os.WriteFile(filename, []byte(privKey), 0600)
}

func LoadPublicKey(filename string) (*big.Int, *big.Int, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, nil, err
	}

	// Decode Base64 and parse n and e
	content := string(data)
	start := "-----BEGIN RSA PUBLIC KEY-----\n"
	end := "\n-----END RSA PUBLIC KEY-----"
	encoded := content[len(start) : len(content)-len(end)]
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, nil, err
	}

	var n, e big.Int
	fmt.Sscanf(string(decoded), "n:%s\ne:%s", &n, &e)

	return &n, &e, nil
}

func LoadPrivateKey(filename string) (*big.Int, *big.Int, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, nil, err
	}

	// Decode Base64 and parse n and d
	content := string(data)
	start := "-----BEGIN RSA PRIVATE KEY-----\n"
	end := "\n-----END RSA PRIVATE KEY-----"
	encoded := content[len(start) : len(content)-len(end)]
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, nil, err
	}

	var n, d big.Int
	fmt.Sscanf(string(decoded), "n:%s\nd:%s", &n, &d)

	return &n, &d, nil
}

// This function takes a file and encrypts it
// Important to note that RSA cannot encrypt data equal to or larger than n so the file needs to be split into chunks
func EncryptFile(inputFile, outputFile, publicKeyFile string) error {
	// Loads n and e from publicKeyFile
	n, e, err := LoadPublicKey(publicKeyFile)

	if err != nil {
		return err
	}

	// Read the input file
	data, err := os.ReadFile(inputFile)
	if err != nil {
		return err
	}

	// Chunk size in bytes (based on key size)
	// -1 to make it less than the modulus n which is required for RSA
	chunkSize := len(n.Bytes()) - 1

	var encryptedChunks []byte
	// i references the start of the chunk and it is appended the size of the chunk to move forward
	for i := 0; i < len(data); i += chunkSize {
		// Get the current chunk
		/*
		   For this to make sense assume that we are at the start of the file where i is at byte 0 and the chunk size is 100
		   the end of the current chunk would be 100 but in the second iteration the i is 100 and the end is 200 effectively choosing the next chunk
		   how ever if the end index extends the end of the data then the end will be the final index of the data which is the len of data
		*/
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunk := data[i:end]

		// Convert chunk to big.Int
		m := new(big.Int).SetBytes(chunk)

		// Encrypt: c = m^e % n
		c := new(big.Int).Exp(m, e, n)

		// Append the encrypted chunk
		encryptedChunks = append(encryptedChunks, c.Bytes()...)
	}

	// Write the encrypted data to the output file
	return os.WriteFile(outputFile, encryptedChunks, 0600)
}

func DecryptFile(inputFile, outputFile, privateKeyFile string) error {
	// Load the private key (n and d) from the file
	n, d, err := LoadPrivateKey(privateKeyFile)
	if err != nil {
		return err
	}

	// Read the encrypted file
	data, err := os.ReadFile(inputFile)
	if err != nil {
		return err
	}

	// Since encryption splits the file into chunks, decryption must process chunks
	chunkSize := len(n.Bytes()) // This matches the modulus size

	var decryptedChunks []byte
	for i := 0; i < len(data); i += chunkSize {
		// Get the current chunk
		/*
		   For this to make sense assume that we are at the start of the file where i is at byte 0 and the chunk size is 100
		   the end of the current chunk would be 100 but in the second iteration the i is 100 and the end is 200 effectively choosing the next chunk
		   how ever if the end index extends the end of the data then the end will be the final index of the data which is the len of data
		*/
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunk := data[i:end]

		// Convert chunk to big.Int
		c := new(big.Int).SetBytes(chunk)

		// Decrypt: m = c^d % n
		m := new(big.Int).Exp(c, d, n)

		// Append the decrypted chunk
		decryptedChunks = append(decryptedChunks, m.Bytes()...)
	}

	// Write the decrypted data to the output file
	return os.WriteFile(outputFile, decryptedChunks, 0600)
}

func RSAKeyGen(bits int) bool {
	n, e, d, _, err := GenerateRSAKeys(BITS)
	if err != nil {
		fmt.Println("Error generating RSA keys:", err)
		return false
	}

	// Save public and private keys to files
	err = SavePublicKey("id_rsa.pub", n, e)
	if err != nil {
		fmt.Println("Error saving public key:", err)
		return false
	}

	err = SavePrivateKey("id_rsa", n, d)
	if err != nil {
		fmt.Println("Error saving private key:", err)
		return false
	}

	return true
}

func main() {

	// TODO: CLI call to RSAKeyGen
	// Example usage
	if !RSAKeyGen(BITS) {
		fmt.Println("An error has occured, Exiting...")
		return
	}
	// TODO: CLI call to EncryptFile
	// First Param is the plain text file, Second Param is the name of the output file to be created, Third Param is the name of the publickey file
	EncryptFile("testfile.txt", "encrypted.txt", "id_rsa.pub")

	// TODO: CLI call to DecryptFile
	// First Param is the encrypted text file, Second Param is the name of the output file to be created, Third Param is the name of the privatekey file
	DecryptFile("encrypted.txt", "decrypted.txt", "id_rsa")

	// TODO: make user customize the constants above using dash (-) options (!! THIS IS OPTIONAL !!)
}
