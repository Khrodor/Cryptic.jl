
module RandomGenerators

export BlumBlumShub, nextnumber!, nextbit!

macro randombitsnumber(source)
    return :(rand(1:(BigInt(1)<<length(bin(source)))))
end

macro randomnumber(source)
    return quote
        local x::BigInt
        x = @randombitsnumber(source)
        while iseven(x)
            x = @randombitsnumber(source)
        end
        source+x
    end
end

function isxmody(number::Number, x::Number, y::Number)
    return number%y == x
end

function iscoprime(x::Number, y::Number)
    return gcd(x,y) == 1
end

type BlumBlumShub
    p::BigInt
    q::BigInt
    n::BigInt
    x::BigInt
    BlumBlumShub(bits::Number)=begin
        local source::BigInt = BigInt(1)<<bits
        local np::BigInt = @randomnumber(source)
        while !isprime(np) || !isxmody(np,3,4)
            np = @randomnumber(source)
        end
        local nq::BigInt = @randomnumber(source)
        while !isprime(nq) || !isxmody(nq,3,4) || nq==np
            nq = @randomnumber(source)
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

function nextnumber!(gen::BlumBlumShub)
    gen.x = (gen.x^2) % gen.n
end

function nextbit!(gen::BlumBlumShub)
    bin(nextnumber!(gen))[end]
end


end
