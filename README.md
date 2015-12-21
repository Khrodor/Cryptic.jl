# Cryptic

# Symetric

#### AES

Contains operations for encrypting data using AES cipher with blocks of 256 bits.

    obj = AES256(key::ASCIIString)

In order to encrypt data you should pass that object to one of cipher block object.

#### Serpent

Contains operations for encrypting data using Serpent cipher with blocks of 128 bits.

    obj = Serpent128(key::ASCIIString)
or 

	obj = Serpent128(key::Array{UInt8})

In order to encrypt data you should pass that object to one of cipher block object. Actually this encrypt algorithm is quite slow, and need some optimization.

# Module CipherBlocks includes:

3 types:

#### ECB:

    constructor ECB(encryptrionType::Any)
    takes selected block encryption type
#### CBC:

    constructor CBC(encryptrionType::Any, initialVetor::Array{UInt8})
    takes selected encryption block type and initial vector for encoding/decoding
#### CFB:

    constructor CFB(encryptrionType::Any, initialVetor::Array{UInt8})
    takes selected encryption block type and initial vector for encoding/decoding
#### Note:
    encryptionType object should contain fields:
     bits - Block size in bits
     key - Key for encryption
     encrypt - Encryption function
     decrypt - Decryption function
     buffer - Buffer with whole initial plain text
2 functions

  encrypt(blocktype)

    Encrypts data given in encryption type object with block of selected type.
    Overwrites data buffer inside encryption type object

  decrypt(blocktype)

    Encrypts data given in encryption type object with block of selected type.
    Overwrites data buffer inside encryption type object


# Module RSA includes:

3 types:

#### RSA1024:

    constuctor RSA1024()
    takes no arguments

    fields:

      publicKey::Array{BigInt} holds generated public key values
      privateKey::Array{BigInt} hold generated private key values
      k::BigInt holds length of plaintext block
      l::BigInt holds length of ciphertext block

#### PublicRSA1024:

    constructor PublicRSA1024(rsa::RSA1024)
    takes as argument RSA1024 object to initalize its fields

    fields:
      publicKey::Array{BigInt} holds generated in rsa object public key values
      k::BigInt holds length of plaintext block
      l::BigInt holds length of ciphertext block

#### PrivRSA1024:

    constructor PrivRSA1024(rsa::RSA1024)
    takes as argument RSA1024 object to initalize its fields

    fields:
      privateKey::Array{BigInt} holds generated in rsa object private key values
      k::BigInt holds length of plaintext block
      l::BigInt holds length of ciphertext block

4 functions:

  encrypt(buf::Union{ASCIIString, IOStream, Array{UInt8}, publicRSA::PublicRSA1024)

    Encrypts data where as a key it takes values from PublicRSA1024 type object.
    returns encrypteddata::Array{UInt8}

  decrypt(buf::Array{UInt8}, privRSA::PrivRSA1024)

    Dectypts data given as result of encrypt function. As a key it takes values from PrivRSA1024 type object.
    returns decrypteddata::Array{UInt8}

  signature(message::Union{Array{UInt8},ASCIIString}, privRSA::PrivRSA1024)

    Creates signature for given message with keys provided in PrivRSA1024 type object.
    returns signature::BigInt

  verifysign(message::Union{Array{UInt8},ASCIIString}, signa::BigInt, publicRSA::PublicRSA1024)

    Verifies provided signature to message with keys given in PublicRSA1024 type object.
    returns result::Bool

Example:
```
  using Cryptic.RSA
  test = Cryptic.RSA.RSA1024();
  publictest = Cryptic.RSA.PublicRSA1024(test);
  privtest = Cryptic.RSA.PrivRSA1024(test);
  entest = Cryptic.RSA.encrypt("Example",publictest);
  Cryptic.RSA.decrypt(entest,privtest)
```

streaming: ( ks )
- a5/* (ks)
- salsa (ks)
- sosemanuk (ks)
- estream (ks)

# Hash functions
#### md5

Standart md5 function, to use call one of functions:

	md5(msg::ASCIIString)
	md5(msg::Array{UInt8})
	md5(file::IO)

md5 is not safe actually.

#### SHA2

Basic SHA2 hashing function that operates on blocks of 256 bits.

    obj = SHA256(string::ASCIIString; file::Bool=true)
    compute!(obj)

SHA256 takes as parameter string, which next will be computed. Normal text that will be computed can be passed, as well as path to file. If file exist, then hash function from this file will be computed.

####  bCrypt

Strong hashing function.

    bcrypt = bCrypt()
    salt::ASCIIString = gensalt(obj::bCrypt, rounds::Int)
    hashpw(obj::bCrypt, stringtohash::ASCIIString, salt::ASCIIString)

In order to compute hash you need to provide string which will be computed, and salt string, that will randomize that hash.

To generate random salt you can use **gensalt** function and provide number of rounds. That number should be greater than 4 and less than 30.

#### Whirpool

Strong hashing 512 bits function, for use simply call one of functions:

	whirpool(msg::ASCIIString)
	whirpool(msg::Array{UInt8})
	whirpool(file::IO)


# Historic

#### Enigma

Simply implementation of 3 rotors enigma with reflector. To use call function:

	enigma(letters::ASCIIString, key:ASCIIString, msg:ASCIIString)

Where letters are in form:

	"AB CD"
	
which means, that we replace A->B, B->A, and C->D, D->C

key is ASCIIString of length 3, if no key is specified or key is less than 3 characters, default key will be established ("ABC")

spaces are not encrypted.

# primality tests: (ks)
- miller-rabin (ks)
- bpsw (ks)
- aks (ks)

# Module RandomGenerators

Every generator contains two function:
- **nextbit!(gen::Any)** - generates next random bit
- **nextnumber!(gen::Any)** - generates next number

#### RSA

    gen=RSA()
    nextbit!(gen)

#### BlumBlumShub

Safety of this generator is based on difficult level to calculate square root modulus composite number.

    gen=BlumBlumShub(bits::Number)
    nextbit!(gen)

Bits parameter is the minimum bits size of defined generator.

#### BlumMicali

Safety of this generator is based on discrete logarithm problem.

    gen=BlumMicali()
    nextbit!(gen)

## Random prime number

#### Gordon algorithm

Algorithm allows to generate strong prime number **p** that meets specific requirements:
- **p - 1** have big prime factor, denoted by **r**
- **p + 1** have big prime factor,
- **r - 1** have big prime factor.


    gordonalgorithm(bits::Number=512)


Bits parameter is the minimum bits size of generated strong prime number.
