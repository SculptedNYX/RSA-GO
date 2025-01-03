# RSA-GO
An RSA Key-gen, Encryption and decryption tool made with GOlang

## File build
`go build -o rsa main.go`

## Usage Example

### Generate Keys
`rsa -action=generate_keys -keyfile=my_rsa`

### Encrypt the File
`rsa -action=encrypt -keyfile=my_rsa_public.pem -input=my_file.txt-output=my_file_encrypted.bin`

### Decrypt the File
`rsa -action=decrypt -keyfile=my_rsa_private.pem -input=my_file_encrypted.bin -output=my_file_decrypted.txt`

