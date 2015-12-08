module RSA
export RSA1024

using RandomGenerators

type RSA1024
    publicKey::Array{BigInt}
    privateKey::Array{BigInt}
    dicN::Int
         
    RSA1024() = begin
        local keys = RSA.generatekeys()
        local publicKey::Array{BigInt} = Array{BigInt}(2)
        local privateKey::Array{BigInt} = Array{BigInt}(2)
        publicKey = [keys[1],keys[2]]
        privateKey = [keys[3],keys[4]]
        new(publicKey, privateKey, 255)
    end 
end

function generatekeys()
    p = gordonalgorithm(1024)
    q = gordonalgorithm(1024)
    na = p * q
    fi = (p - 1)*(q - 1)
    ea = rand(1:fi)
    while gcd(ea,fi) != 1
        ea = rand(1:fi)
    end
    da = invmod(ea,fi)
    return [[na,ea];[na,da]]
end

end