
module Md5

export md5

    function md5(msg::Array{UInt8} )
        K = zeros(UInt32, 64)
        s = zeros(UInt32, 64)
        originlength::UInt64 = length(msg) * 8
        s[1:64] =
            [7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
            7, 12, 17, 22, 5,  9, 14, 20,  5,  9, 14, 20,  5,  9,
            14, 20, 5,  9, 14, 20, 4, 11, 16, 23,  4, 11, 16, 23,
            4, 11, 16, 23,  4, 11, 16, 23, 6, 10, 15, 21,  6, 10,
            15, 21,  6, 10, 15, 21,  6, 10, 15, 21 ]

        for i in 1:64
            K[i] = floor(2^32 * abs(sin(i)))
        end
        #init values
        a0::UInt32 = 0x67452301
        b0::UInt32 = 0xefcdab89
        c0::UInt32 = 0x98badcfe
        d0::UInt32 = 0x10325476

        #append bit "1" to msg
        push!(msg, 0x80)

        while length(msg) % (512 / 8) < (448 / 8)
            push!(msg, 0)
        end

        #add original msg size in bits as 64 bits
        byte::UInt8 = 0
        mask::UInt64 = 0xff
        for i in 1:8
             byte = byte | ((originlength >> (i-1) * 8) & mask)
            push!(msg, byte)
            byte = 0;
        end

        mod = 0xffffffff

        for i in 1:512:length(msg)*8
            #break 512 bits into 16x32bits
            M = zeros(UInt32, 16)
            for j in 1:16
                tmp::UInt32 = 0
                for k in 1:4
                    tmp = (tmp << 8) | msg[i+(j - 1)*4+4-k]
                end
                M[j] = tmp;
            end

            A::UInt32 = a0
            B::UInt32 = b0
            C::UInt32 = c0
            D::UInt32 = d0

            #main loop
            for j in 1:64
                F::UInt32 = 0
                if j <= 16
                    #println("<= 16 ", j)
                    F = (B & C) | ((~B) & D)
                    g = j 
                elseif j <= 32
                    #println("<= 32 ", j)
                    F = (D & B) | ((~D) & C)
                    g = ((5*(j - 1) + 1) % 16) + 1
                elseif j <= 48
                    #println("<= 48 ", j)
                    F = B $ C $ D
                    g = (3 * (j - 1) + 5) % 16 + 1
                else
                    #println("<= 64 ", j)
                    F = C $ (B | (~D))
                    g = (7 * (j - 1)) % 16 + 1
                end
                dTemp = D
                D = C
                C = B
                B = (B + leftrotate((A + F +K[j] +M[g]), s[j]) ) 
                A = dTemp
            end
            a0 = (a0 + A) 
            b0 = (b0 + B) 
            c0 = (c0 + C)
            d0 = (d0 + D) 
        end

        ret = string(hex(reversebytes(a0)),hex(reversebytes(b0)), hex(reversebytes(c0)), hex(reversebytes(d0)))
        #print(hex(reversebytes(a0)),hex(reversebytes(b0)), hex(reversebytes(c0)), hex(reversebytes(d0)))
        return ret
    end


    function md5(msg::ASCIIString)
        return md5(stringtobytearray(msg))
    end
    
    function md5(file::IO)
        bytes = readbytes(file)
        md5(bytes)
    end

    function leftrotate(x::UInt32, c::UInt32)
        return ((x << c) | (x >> (32 - c)))
    end

    function reversebytes(x::UInt32)
        return ((x & 0x000000ff) <<24) | (x >>24) | ((x & 0x00ff0000) >>8)  | ((x & 0x0000ff00) <<8)
    end

    function stringtobytearray(str::ASCIIString)
        ret = zeros(UInt8, 0)
        for i in str
            push!(ret, convert(UInt8, i))
        end
        return ret
    end
end
