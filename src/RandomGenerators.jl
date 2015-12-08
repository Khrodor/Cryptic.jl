module RandomGenerators

importall PrimeTests
export BlumBlumShub, nextnumber!, nextbit!, gordonalgorithm

function randombitsnumber(source::Number) 
    local len::Number = length(bin(source))
    if len > 3
        return rand((BigInt(1)<<(len-2)):(BigInt(1)<<len))
    end
    return rand(1:BigInt(1)<<len)
end

function randomnumber(source::Number)
    local x::BigInt
    x = randombitsnumber(source)
    return x
end

function randomprimenumber(source::Number)
    local x::BigInt
    x = randomnumber(source)
    while !millerRabin(x)
        x = randomnumber(source)
    end
    return x
end

function isxmody(number::Number, x::Number, y::Number)
    return number%y == x
end

#checks if numbers are coprime
function iscoprime(x::Number, y::Number)
    return gcd(x,y) == 1
end

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
        nx = (nx^2) % nn
        new(np,nq,nn,nx)
    end
end

#get next number from generator
function nextnumber!(gen::BlumBlumShub)
    gen.x = (gen.x^2) % gen.n
end

#get next bit from generator
function nextbit!(gen::BlumBlumShub)
    bin(nextnumber!(gen))[end]
end

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
