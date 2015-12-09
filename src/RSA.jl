module RSA
export RSA1024, encrypt, decrypt

using RandomGenerators

type RSA1024
    publicKey::Array{BigInt}
    privateKey::Array{BigInt}
    dicN::Int
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
        new(publicKey, privateKey, 255, k, l)
    end 
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

function encrypt(buf::ASCIIString, rsa::RSA1024, file::Bool=false) 
    if isfile(buf) && file
        stream::IOStream = open(buf)
        databuffer = readall(stream)
        close(stream)
    else
        databuffer = buf
    end
    blockCount = Int(ceil(length(databuffer) / rsa.k))
    bufarray = Array{UInt8}(rsa.k)
    encryptedtext = Array{UInt8}(0)
    encryptedblocks = Array{BigInt}(0)
    for cnt1 in 1:blockCount
        if cnt1*rsa.k < length(databuffer)
            bufarray = Array{UInt8}(databuffer[ ((cnt1-1)*rsa.k)+1 : cnt1*rsa.k])
        else
            bufarray = Array{UInt8}(databuffer[ ((cnt1-1)*rsa.k)+1 : end ])
            append!(bufarray,[UInt8('.');Array{UInt8}(rand(47:255,rsa.k-length(bufarray)-1))])
        end
        m=BigInt(0)
        for cnt2 in 1:length(bufarray)
            m+=BigInt(bufarray[cnt2])*(255^(rsa.k-cnt2))
        end
        push!(encryptedblocks,powermod(m,rsa.publicKey[2],rsa.publicKey[1]))
    end
    for cnt3 in 1:length(encryptedblocks)
        temp = encryptedblocks[cnt3]
        for cnt4 in 1:rsa.l
            letter = UInt8(floor(temp/(255^(rsa.l-cnt4))))
            temp -= Int(letter)*(255^(rsa.l-cnt4))
            push!(encryptedtext,letter)
        end
    end
    return encryptedtext
end

function decrypt(buf::Array{UInt8}, rsa::RSA1024)
    blockCount = Int(ceil(length(buf) / rsa.l))
    decblocks = Array{BigInt}(0)
    for cnt1 in 1:blockCount
        m = BigInt(0)
        decblock = buf[(cnt1-1)*rsa.l+1 : cnt1*rsa.l]
        for cnt2 in 1:length(decblock)
            m+= BigInt(decblock[cnt2])*(255^(rsa.l-cnt2))
        end
        push!(decblocks,powermod(m,rsa.privateKey[2],rsa.privateKey[1]))
    end
    decryptedtext = Array{UInt8}(0)
    for cnt3 in 1:length(decblocks)
        temp = decblocks[cnt3]
        for cnt4 in 1:rsa.k
            letter = UInt8(floor(temp/(255^(rsa.k-cnt4))))
            temp -= BigInt(letter)*(255^(rsa.k-cnt4))
            push!(decryptedtext, letter)
        end
    end
    decryptedtext = removePadding!(decryptedtext)
    return ASCIIString(decryptedtext)
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