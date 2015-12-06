

module AES

export AES256, setbuffer!

type AES256
    key::Array{UInt8}
    enckey::Array{UInt8}
    deckey::Array{UInt8}
    buffer::Array{UInt8}
    bits::Int64
    encrypt::Function
    decrypt::Function
    
    AES256(key)=begin
        local encKey::Array{UInt8} = Array{UInt8}(32)
        local decKey::Array{UInt8} = Array{UInt8}(32)
        local rcon::UInt8 = 1
        for i in 1:1:32
            if i > length(key)
                encKey[i]=decKey[i]=0x00
            else
                encKey[i]=decKey[i]=key[i]
            end
        end
        
        for i in 7:-1:1
            rcon = aesexpandenckey!(decKey, rcon)
        end
        new(zeros(UInt8, 32), encKey, decKey, zeros(UInt8), 256, encrypt, decrypt)
    end
end

function setbuffer!(ctx::AES256, buf::ASCIIString; file::Bool=true)
    if isfile(buf) && file
        f::IOStream = open(buf)
        content::ASCIIString=readall(f)
        close(f)
        ctx.buffer=Vector{UInt8}(content)
    else
        ctx.buffer=Vector{UInt8}(buf)
    end
    return ctx
end

f(x) = (((x)<<1) $ ((((x)>>7) & 1) * 0x1b))
fd(x) = (((x) >> 1) $ (((x) & 1) != 0 ? 0x8d : 0))
    
#calculate anti-logarithm gen 3
function gfalog(x::UInt8) 
    local atb::UInt8 = 1
    local z::UInt8 = 0
    while x > 0 
        x -= 1
        z = atb
        atb <<= 1
        if (z & 0x80) > 0
            atb $= 0x1b
        end
        atb $= z
    end
    return atb
end

#calculate logarithm gen 3
function gflog(x::UInt8) 
    local atb::UInt8 = 1
    local i::UInt16 = 0
    local z::UInt8 = 0
    while i < 256
        if atb == x 
            break
        end
        z = atb
        atb <<= 1
        if (z & 0x80) > 0
            atb $= 0x1b
        end
        atb $= z
        i += 1
    end
    return UInt8(i & 0xff)
end

#calculate multiplicative inverse
gfmulinv(x::UInt8) = (x != 0) ? gfalog(UInt8(255) - gflog(x)) : 0 

function rjsbox(x::UInt8)
    local y::UInt8 = sb::UInt8 = gfmulinv(x)
    
    y = (y<<1)|(y>>7)
    sb $= y
    y = (y<<1)|(y>>7)
    sb $= y
    
    y = (y<<1)|(y>>7)
    sb $= y
    y = (y<<1)|(y>>7)
    sb $= y

    return (sb $ 0x63)
end

function rjsboxinv(x::UInt8)
    local y::UInt8 = x $ 0x63
    local sb::UInt8 = y = (y<<1)|(y>>7)
    y = (y<<2)|(y>>6)
    sb $= y
    y = (y<<3)|(y>>5)
    sb $= y

    return gfmulinv(sb)
end
        
rjxtime(x::UInt8) = (x & 0x80) > 0 ? ((x << 1) $ 0x1b) : (x << 1)

function aessubbytes!(buf::Array{UInt8})
    local i::UInt8 = 17
    while i > 1
        i -= 1
        buf[i] = rjsbox(buf[i])
    end
end

function aessubbytesinv!(buf::Array{UInt8})
    local i::UInt8 = 17
    while i > 1
        i -= 1
        buf[i] = rjsboxinv(buf[i])
    end
end

function aesaddroundkey!(buf::Array{UInt8}, key::AbstractArray{UInt8})
    local i::UInt8 = 17
    while i > 1
        i -= 1
        buf[i] $= key[i]
    end
end

function aesaddroundkeycpy!(buf::Array{UInt8}, key::Array{UInt8}, cpk::Array{UInt8})
    i::UInt8 = 17
    while i > 1
        i -= 1
        buf[i] $= (cpk[i] = key[i])
        cpk[16+i] = key[16 + i]
    end
end

function aesshiftrows!(buf::Array{UInt8})
    local i::UInt8 = 0
    local j::UInt8 = 0

    i = buf[1]; buf[1] = buf[5]; buf[5] = buf[9]; buf[9] = buf[13]; buf[13] = i;
    i = buf[10]; buf[10] = buf[2]; buf[2] = i;
    j = buf[3]; buf[3] = buf[15]; buf[15] = buf[11]; buf[11] = buf[7]; buf[7] = j
    j = buf[14]; buf[14] = buf[6]; buf[6]  = j;
end

function aesshiftrowsinv!(buf::Array{UInt8})
    local i::UInt8 = 0
    local j::UInt8 = 0

    i = buf[1]; buf[1] = buf[13]; buf[13] = buf[9]; buf[9] = buf[5]; buf[5] = i;
    i = buf[2]; buf[2] = buf[10]; buf[10] = i;
    j = buf[3]; buf[3] = buf[7]; buf[7] = buf[11]; buf[11] = buf[15]; buf[15] = j;
    j = buf[6]; buf[6] = buf[14]; buf[14] = j;
end

function aesmixcolumns!(buf::Array{UInt8})
    local i::UInt8 = 0
    local a::UInt8 = 0
    local b::UInt8 = 0
    local c::UInt8 = 0
    local d::UInt8 = 0
    local e::UInt8 = 0
    
    for i in 1:4:16
        a = buf[i]; b = buf[i + 1]; c = buf[i + 2]; d = buf[i + 3];
        e = a $ b $ c $ d;
        buf[i] $= e $ rjxtime(a$b);   buf[i+1] $= e $ rjxtime(b$c);
        buf[i+2] $= e $ rjxtime(c$d); buf[i+3] $= e $ rjxtime(d$a);
    end
end

function aesmixcolumnsinv!(buf::Array{UInt8})
    local i::UInt8 = 0
    local a::UInt8 = 0
    local b::UInt8 = 0
    local c::UInt8 = 0
    local d::UInt8 = 0
    local e::UInt8 = 0
    local x::UInt8 = 0
    local y::UInt8 = 0
    local z::UInt8 = 0
    
    for i in 1:4:16
        a = buf[i]; b = buf[i + 1]; c = buf[i + 2]; d = buf[i + 3];
        e = a $ b $ c $ d;
        z = rjxtime(e);
        x = e $ rjxtime(rjxtime(z$a$c));  y = e $ rjxtime(rjxtime(z$b$d));
        buf[i] $= x $ rjxtime(a$b);   buf[i+1] $= y $ rjxtime(b$c);
        buf[i+2] $= x $ rjxtime(c$d); buf[i+3] $= y $ rjxtime(d$a);
    end
end

function aesexpandenckey!(k::Array{UInt8}, rc::UInt8) 
    local i::UInt8 = 0

    k[1] $= rjsbox(k[30]) $ rc
    k[2] $= rjsbox(k[31])
    k[3] $= rjsbox(k[32])
    k[4] $= rjsbox(k[29])
    rc = f(rc)

    for i in 5:4:15
        k[i] $= k[i-4]
        k[i+1] $= k[i-3]
        k[i+2] $= k[i-2]
        k[i+3] $= k[i-1]
    end
    
    k[17] $= rjsbox(k[13])
    k[18] $= rjsbox(k[14])
    k[19] $= rjsbox(k[15])
    k[20] $= rjsbox(k[16])

    for i in 21:4:31
        k[i] $= k[i-4]
        k[i+1] $= k[i-3]
        k[i+2] $= k[i-2]
        k[i+3] $= k[i-1]
    end
    
    return rc
end

function aesexpanddeckey!(k::Array{UInt8}, rc::UInt8) 
    local i::UInt8 = 0
    
    for i in 29:-4:18
        k[i] $= k[i-4]
        k[i+1] $= k[i-3]
        k[i+2] $= k[i-2]
        k[i+3] $= k[i-1]
    end

    k[17] $= rjsbox(k[13])
    k[18] $= rjsbox(k[14])
    k[19] $= rjsbox(k[15])
    k[20] $= rjsbox(k[16])

    for i in 13:-4:5
        k[i] $= k[i-4]
        k[i+1] $= k[i-3]
        k[i+2] $= k[i-2]
        k[i+3] $= k[i-1]
    end

    rc = fd(rc);
    k[1] $= rjsbox(k[30]) $ rc
    k[2] $= rjsbox(k[31])
    k[3] $= rjsbox(k[32])
    k[4] $= rjsbox(k[29])
    
    return rc
end

function encrypt(buf::Array{UInt8}, key::Array{UInt8})
    local i::UInt8 = 1
    local rcon::UInt8 = 1
    
    aesaddroundkeycpy!(buf, key, key)
    for i in 1:1:13
        aessubbytes!(buf)
        aesshiftrows!(buf)
        aesmixcolumns!(buf)
        if (i & 1) > 0
            aesaddroundkey!(buf, sub(key, 16:32))
        else 
            rcon = aesexpandenckey!(key, rcon)
            aesaddroundkey!(buf, key)
        end
    end
    aessubbytes!(buf)
    aesshiftrows!(buf)
    aesexpandenckey!(key, rcon)
    aesaddroundkey!(buf, key)
    return buf
end

function decrypt(buf::Array{UInt8}, key::Array{UInt8})
    local i::UInt8 = 13
    local rcon::UInt8 = 0x80

    aesaddroundkeycpy!(buf, key, key)
    aesshiftrowsinv!(buf)
    aessubbytesinv!(buf)

    while i > 0
        if (i & 1) > 0
            rcon = aesexpanddeckey!(key, rcon)
            aesaddroundkey!(buf, sub(key, 16:32))
        else 
            aesaddroundkey!(buf, key)
        end
        aesmixcolumnsinv!(buf)
        aesshiftrowsinv!(buf)
        aessubbytesinv!(buf)
        i-=1
    end
    aesaddroundkey!(buf, key)
    return buf
end
        
#tests
function tests()
    assert(gfalog(UInt8(151)) == UInt8(192))
    assert(gfalog(UInt8(253)) == UInt8(82))

    assert(gflog(UInt8(11)) == UInt8(104))
    assert(gflog(UInt8(5)) == UInt8(2))

    assert(gfmulinv(UInt8(43)) == UInt8(21))
    assert(gfmulinv(UInt8(107)) == UInt8(223))

    assert(rjsbox(UInt8(0)) == UInt8(99))
    assert(rjsbox(UInt8(11)) == UInt8(43))

    assert(rjsboxinv(UInt8(105)) == UInt8(228))
    assert(rjsboxinv(UInt8(206)) == UInt8(236))

    assert(rjxtime(UInt8(232)) == UInt8(203))
    assert(rjxtime(UInt8(10)) == UInt8(20))

    #aessubbytesinv
    testarrayaessubbytesinv::Array{UInt8} = [187, 37, 63, 68, 233, 109, 200, 238, 123, 16, 177, 103, 99, 59, 206, 105]
    resultaessubbytesinv::Array{UInt8} = [254, 194, 37, 134, 235, 179, 177, 153, 3, 124, 86, 10, 0, 73, 236, 228]
    aessubbytesinv!(testarrayaessubbytesinv)
    assert(length(setdiff(testarrayaessubbytesinv,resultaessubbytesinv)) == 0)
    #--------------#
    
    #aesaddroundkey
    testaesaddroundkeybuf::Array{UInt8} = [254, 194, 37, 134, 235, 179, 177, 153, 3, 124, 86, 10, 0, 73, 236, 228]
    testaesaddroundkeykey::Array{UInt8} = [234, 228, 240, 137, 19, 203, 168, 178, 37, 100, 95,202, 60, 211, 47, 74, 105, 110, 102, 111, 114, 109, 97, 116, 121, 107, 97, 0, 0, 0, 0, 0]
    resultaesaddroundkey::Array{UInt8} = [20, 38, 213, 15, 248, 120, 25, 43, 38, 24, 9, 192, 60, 154, 195, 174]
    aesaddroundkey!(testaesaddroundkeybuf, testaesaddroundkeykey)
    assert(length(setdiff(testaesaddroundkeybuf,resultaesaddroundkey)) == 0)
    #--------------#
    
    #aesaddroundkeycpy
    testaesaddroundkeycpykey::Array{UInt8} = [125, 156, 95, 194, 59, 235, 124, 120, 142, 180, 241, 78, 134, 247, 56, 21, 174, 140, 247, 208, 189, 71, 95, 98, 152, 35, 0, 168, 164, 240, 47, 226]
    testaesaddroundkeycpybuf::Array{UInt8} = [198, 241, 238, 171, 210, 251, 178, 60, 245, 143, 206, 160, 229, 210, 240, 114]
    testaesaddroundkeycpycpk::Array{UInt8} = Array{UInt8}(32)
    resultaesaddroundkeycpy::Array{UInt8} = [187, 109, 177, 105, 233, 16, 206, 68, 123, 59, 63, 238, 99, 37, 200, 103]
    aesaddroundkeycpy!(testaesaddroundkeycpybuf, testaesaddroundkeycpykey, testaesaddroundkeycpycpk)
    assert(length(setdiff(testaesaddroundkeycpybuf,resultaesaddroundkeycpy)) == 0)
    assert(length(setdiff(testaesaddroundkeycpykey,testaesaddroundkeycpycpk)) == 0)
    #--------------#
    
    #aesshiftrowsinv
    testaesshiftrowsinv::Array{UInt8} = [187, 109, 177, 105, 233, 16, 206, 68, 123, 59, 63, 238, 99, 37, 200, 103]
    resultaesshiftrowsinv::Array{UInt8} = [187, 37, 63, 68, 233, 109, 200, 238, 123, 16, 177, 103, 99, 59, 206, 105]
    aesshiftrowsinv!(testaesshiftrowsinv)
    assert(length(setdiff(testaesshiftrowsinv,resultaesshiftrowsinv)) == 0)
    #--------------#
    
    #aesmixcolumnsinv
    testaesmixcolumnsinv::Array{UInt8} = [20, 38, 213, 15, 248, 120, 25, 43, 38, 24, 9, 192, 60, 154, 195, 174]
    resultaesmixcolumnsinv::Array{UInt8} = [176, 150, 186, 116, 31, 184, 129, 148, 232, 121, 50, 84, 115, 49, 1, 136]
    aesmixcolumnsinv!(testaesmixcolumnsinv)
    assert(length(setdiff(testaesmixcolumnsinv,resultaesmixcolumnsinv)) == 0)
    #--------------#
    
    #aesexpanddeckey
    testaesexpanddeckey::Array{UInt8} = [125, 156, 95, 194, 59, 235, 124, 120, 142, 180, 241, 78, 134, 247, 56, 21, 174, 140, 247, 208, 189, 71, 95, 98, 152, 35, 0, 168, 164, 240, 47, 226]
    testrcaesexpanddeckey::UInt8 = 128
    resultaesexpanddeckey::Array{UInt8} = [91, 137, 137, 41, 70, 119, 35, 186, 181, 95, 141, 54, 8, 67, 201, 91, 234, 228, 240, 137, 19, 203, 168, 178, 37, 100, 95, 202, 60, 211, 47, 74]
    aesexpanddeckey!(testaesexpanddeckey, testrcaesexpanddeckey)
    assert(length(setdiff(testaesexpanddeckey,resultaesexpanddeckey)) == 0)
    #--------------#
    
    #aessubbytes
    testaessubbytes::Array{UInt8} = [206, 91, 202, 206, 76, 47, 217, 126, 131, 93, 59, 44, 25, 227, 44, 95]
    resultaessubbytes::Array{UInt8} = [139, 57, 116, 139, 41, 21, 53, 243, 236, 76, 226, 113, 212, 17, 113, 207]
    aessubbytes!(testaessubbytes)
    assert(length(setdiff(testaessubbytes,resultaessubbytes)) == 0)
    #--------------#
    
    #aesshiftrows
    testaesshiftrows::Array{UInt8} = [192, 4, 69, 51, 129, 137, 236, 97, 155, 67, 77, 251, 232, 120, 190, 202]
    resultaesshiftrows::Array{UInt8} = [192, 137, 77, 202, 129, 67, 190, 51, 155, 120, 69, 97, 232, 4, 236, 251]
    aesshiftrows!(testaesshiftrows)
    assert(length(setdiff(testaesshiftrows,resultaesshiftrows)) == 0)
    #--------------#
    
    #aesmixcolumns
    testaesmixcolumns::Array{UInt8} = [34, 51, 89, 244, 117, 4, 107, 115, 190, 216, 168, 177, 152, 123, 150, 174]
    resultaesmixcolumns::Array{UInt8} = [188, 91, 164, 255, 254, 179, 50, 22, 13, 71, 229, 208, 158, 97, 61, 25]
    aesmixcolumns!(testaesmixcolumns)
    assert(length(setdiff(testaesmixcolumns,resultaesmixcolumns)) == 0)
    #--------------#
    
    #aesexpandenckey
    testaesexpandenckey::Array{UInt8} = [105, 110, 102, 111, 114, 109, 97, 116, 121, 107, 97, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    testrcaesexpandenckey::UInt8 = 1
    resultaesexpandenckey::Array{UInt8} = [1, 11, 13, 5, 12, 121, 96, 100, 120, 0, 11, 5, 120, 0, 11, 5, 120, 99, 43, 107, 188, 99, 43, 107, 188, 99, 43, 107, 188, 99, 43, 107, 188]
    aesexpandenckey!(testaesexpandenckey, testrcaesexpandenckey)
    assert(length(setdiff(testaesexpandenckey,resultaesexpandenckey)) == 0)
    #--------------#
    
    #type
    aesobj::AES256 = AES256("informatyka")
    resultaesobjenckey::Array{UInt8}=[105, 110, 102, 111, 114, 109, 97, 116, 121, 107, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    resultaesobjdeckey::Array{UInt8}=[125, 156, 95, 194, 59, 235, 124, 120, 142, 180, 241, 78, 134, 247, 56, 21, 174, 140, 247, 208, 189, 71, 95, 98, 152, 35, 0, 168, 164, 240, 47, 226]
    resultaesobjkey::Array{UInt8}=zeros(UInt8, 32)
    assert(length(setdiff(aesobj.key,resultaesobjkey)) == 0)
    assert(length(setdiff(aesobj.enckey,resultaesobjenckey)) == 0)
    assert(length(setdiff(aesobj.deckey,resultaesobjdeckey)) == 0)
    #--------
    
    #encrypt/decrypt
    encaesobj::AES256 = AES256("encrypting")
    fraze::ASCIIString = "encryptordecrypt"
    setbuffer!(encaesobj, fraze)
    encrypt(encaesobj.buffer, encaesobj.enckey)
    decrypt(encaesobj.buffer, encaesobj.deckey)
    assert(length(setdiff(encaesobj.buffer, Vector{UInt8}("encryptordecrypt"))) == 0)
    #--------
end
#endtests

tests()

end

