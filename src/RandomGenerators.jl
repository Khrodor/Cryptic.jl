module RandomGenerators

using Cryptic.PrimeTests

export BlumBlumShub, RSA, BlumMicali, nextnumber!, nextbit!, gordonalgorithm

function randombitsnumber(source::Number) 
    local len::Number = length(bin(source))
    if len > 3
        return rand((BigInt(1)<<(len-2)):(BigInt(1)<<len))
    end
    return rand(1:BigInt(1)<<len)
end

randomnumber(source::Number) = randombitsnumber(source)

function randomprimenumber(source::Number)
    local x::BigInt
    x = randomnumber(source)
    while !millerRabin(x)
        x = randomnumber(source)
    end
    return x
end

isxmody(number::Number, x::Number, y::Number) = number%y == x

#checks if numbers are coprime
iscoprime(x::Number, y::Number) = gcd(x,y) == 1

#blum blum shub generator
type BlumBlumShub
    p::BigInt
    q::BigInt
    n::BigInt
    x::BigInt
    BlumBlumShub(bits::Number)=begin
        local source::BigInt = BigInt(1)<<bits
        local np::BigInt = randomnumber(source)
        while !millerRabin(np) || !isxmody(np,3,4)
            np = randomnumber(source)
        end
        local nq::BigInt = randomnumber(source)
        while !millerRabin(nq) || !isxmody(nq,3,4) || nq==np
            nq = randomnumber(source)
        end
        local nn::BigInt = np*nq
        local nx::BigInt = rand(big(2:nn))
        while !iscoprime(nx,nn)
            nx = rand(big(2:nn))
        end
        nx = powermod(nx, 2, nn)
        new(np,nq,nn,nx)
    end
end

#get next number from generator
nextnumber!(gen::BlumBlumShub) = gen.x = powermod(gen.x, 2, gen.n)
#get next bit from generator
nextbit!(gen::BlumBlumShub) = bin(nextnumber!(gen))[end] == '1' ? 1 : 0

type BlumMicali
    p::BigInt
    g::BigInt
    xi::BigInt
    BlumMicali()=begin
        local p::BigInt = rand((BigInt(1)<<512):(BigInt(1)<<2048))
        while !millerRabin(p)
            p = rand((BigInt(1)<<512):(BigInt(1)<<2048))
        end
        local g::BigInt = rand((BigInt(1)<<256):(BigInt(1)<<512))
        while !millerRabin(g)
            g = rand((BigInt(1)<<256):(BigInt(1)<<512))
        end
        local x0::BigInt = rand(7:p)
        while !millerRabin(x0)
            x0 = rand(7:p)
        end
        new(p, g, powermod(g,x0,p))
    end
end

nextnumber!(gen::BlumMicali) = gen.xi = powermod(gen.g, gen.xi, gen.p)
nextbit!(gen::BlumMicali) = nextnumber!(gen) < div(gen.p-1, 2) ? 1 : 0

type RSA
    e::BigInt
    n::BigInt
    xi::BigInt
    RSA()=begin
        local p::BigInt=rand((BigInt(1)<<512):(BigInt(1)<<2048))
        while !millerRabin(p)
            p=rand((BigInt(1)<<512):(BigInt(1)<<2048))
        end
        local q::BigInt=rand((BigInt(1)<<512):(BigInt(1)<<2048))
        while !millerRabin(q)
            q=rand((BigInt(1)<<512):(BigInt(1)<<2048))
        end
        local n::BigInt=p*q
        local e::BigInt=rand((BigInt(1)<<256):n)
        while !iscoprime(e, n)
            e=rand((BigInt(1)<<256):n)
        end
        local x0=rand((BigInt(1)<<256):n)
        new(e,n,powermod(x0,e,n))
    end
end

nextnumber!(gen::RSA) = gen.xi = powermod(gen.xi, gen.e, gen.n)
nextbit!(gen::RSA) = bin(nextnumber!(gen))[end] == '1' ? 1 : 0

#strong prime number generator
function gordonalgorithm(bits::Number=512)
    local value::BigInt = BigInt(1)<<div(bits,2)
    local s::BigInt = randomprimenumber(value)
    local t::BigInt = randomprimenumber(value)
    
    local i0::BigInt = rand(3:13)
    while !millerRabin((2*i0*t)+1)
        i0 += 1
    end
    local r::BigInt = (2*i0*t)+1
    
    local p0::BigInt = 2*powermod(s,r-2,r)*s-1
    
    local j0::BigInt = rand(3:13)
    while !millerRabin(p0+2*j0*r*s)
        j0 += 1
    end
    return p0+2*j0*r*s
end

end
