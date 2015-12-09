module RSA
export RSA1024, PublicRSA1024, PrivRSA1024, encrypt, decrypt, sigature, verifysign

using RandomGenerators

type RSA1024
    publicKey::Array{BigInt}
    privateKey::Array{BigInt}
    k::BigInt
    l::BigInt
         
    RSA1024() = begin
        local keys = RSA.generatekeys()
        local publicKey::Array{BigInt} = Array{BigInt}(2)
        local privateKey::Array{BigInt} = Array{BigInt}(2)
        local k = BigInt(0)
        local l = BigInt(0)
        publicKey = [keys[1],keys[2]]
        privateKey = [keys[3],keys[4]]
        k =  Int(ceil(log(BigInt(255),publicKey[1]))) - 2
        l =  Int(ceil(log(BigInt(255),publicKey[1]))) + 2
        new(publicKey, privateKey, k, l)
    end 
end

type PublicRSA1024
    publicKey::Array{BigInt}
    k::BigInt
    l::BigInt
end

type PrivRSA1024
    privateKey::Array{BigInt}
    k::BigInt
    l::BigInt
end

function generatekeys()
    p = gordonalgorithm(1024)
    q = gordonalgorithm(1024)
    while gcd(p-1,q-1) > 3 && abs(length(digits(p))-length(digits(q))) < 5  
        p = gordonalgorithm(1024)
        q = gordonalgorithm(1024)
    end
    na = p * q
    fi = (p - 1)*(q - 1)
    ea = rand(1:fi)
    while gcd(ea,fi) != 1
        ea = rand(1:fi)
    end
    da = invmod(ea,fi)
    return [[na,ea];[na,da]]
end

function encrypt(buf::ASCIIString, publicRSA::PublicRSA1024, file::Bool=false) 
    if isfile(buf) && file
        stream::IOStream = open(buf)
        databuffer = readall(stream)
        close(stream)
    else
        databuffer = buf
    end
    blockCount = Int(ceil(length(databuffer) / publicRSA.k))
    bufarray = Array{UInt8}(publicRSA.k)
    encryptedtext = Array{UInt8}(0)
    encryptedblocks = Array{BigInt}(0)
    for cnt1 in 1:blockCount
        if cnt1*publicRSA.k < length(databuffer)
            bufarray = Array{UInt8}(databuffer[ ((cnt1-1)* publicRSA.k)+1 : cnt1*publicRSA.k])
        else
            bufarray = Array{UInt8}(databuffer[ ((cnt1-1)* publicRSA.k)+1 : end ])
            append!(bufarray,[UInt8('.');Array{UInt8}(rand(47:255, publicRSA.k-length(bufarray)-1))])
        end
        m=calcm(bufarray,  publicRSA.k)
        push!(encryptedblocks,powermod(m,publicRSA.publicKey[2],publicRSA.publicKey[1]))
    end
    for cnt3 in 1:length(encryptedblocks)
        letterset = encryptedblocks[cnt3]
        append!(encryptedtext,getletters(letterset,publicRSA.l))
    end
    return encryptedtext
end

function decrypt(buf::Array{UInt8}, privRSA::PrivRSA1024)
    blockCount = Int(ceil(length(buf) / privRSA.l))
    decblocks = Array{BigInt}(0)
    for cnt1 in 1:blockCount
        decblock = buf[(cnt1-1)*privRSA.l+1 : cnt1*privRSA.l]
        m = calcm(decblock, privRSA.l)
        push!(decblocks,powermod(m,privRSA.privateKey[2],privRSA.privateKey[1]))
    end
    decryptedtext = Array{UInt8}(0)
    for cnt3 in 1:length(decblocks)
        letterset = decblocks[cnt3]
        append!(decryptedtext,getletters(letterset,privRSA.k))
    end
    decryptedtext = removePadding!(decryptedtext)
    return ASCIIString(decryptedtext)
end

function getletters(num::BigInt, len::BigInt)
    letters = Array{UInt8}(0)
    temp = num
    for cnt in 1:len
        letter = UInt8(floor(temp/(255^(len-cnt))))
        temp -= BigInt(letter)*(255^(len-cnt))
        push!(letters, letter)
    end
    return letters
end

function signature(message::ASCIIString, privRSA::PrivRSA1024)
    m = calcm(Array{UInt8}(message), BigInt(length(message)))
    h = hash(m)
    s = h % privRSA.privateKey[1]
    return powermod(s,privRSA.privateKey[2],privRSA.privateKey[1])
end

function verifysign(message::ASCIIString, signa::BigInt, publicRSA::PublicRSA1024)
    m = calcm(Array{UInt8}(message), BigInt(length(message)))
    w = powermod(signa,publicRSA.publicKey[2],publicRSA.publicKey[1])
    v = hash(m) % publicRSA.publicKey[1]
    return v == w
end

function calcm(arr::Array{UInt8}, len::BigInt)
    m = BigInt(0)
    for cnt in 1:length(arr)
        m+= BigInt(arr[cnt])*(255^(len-cnt))
    end
    return m
end

function removePadding!(arr::Array{UInt8})
    startPadding = findlast(arr,UInt8('.'))
    if(startPadding >= length(arr) || startPadding == 0)
        return arr
    elseif findfirst(arr[startPadding+1:end],UInt8('.')) == 0
        return arr[1:startPadding-1]
    end
    return arr
end

end