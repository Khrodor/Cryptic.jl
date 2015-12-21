module Cryptic

# package code goes here

include("SHA2.jl")
include("AES.jl")
include("PrimeTests.jl")
include("RandomGenerators.jl")
include("CipherBlocks.jl")
include("RSA.jl")
include("BCrypt.jl")
include("Enigma.jl")
include("md5.jl")
include("Serpent.jl")
include("Whirpool.jl")
export SHA2, AES, PrimeTests, RandomGenerators, CipherBlocks, RSA, BCrypt, enigma, whirpool, md5, serpentencrypt, serpentdecrypt

end # module
