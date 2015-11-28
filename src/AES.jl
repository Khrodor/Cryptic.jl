
module AES

export AES256, setBuffer!

type AES256
    key::Array{UInt8}
    enckey::Array{UInt8}
    deckey::Array{UInt8}
    buffer::Array{UInt8}
    
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
            rcon = aesExpandEncKey!(decKey, rcon)
        end
        new(zeros(UInt8, 32), encKey, decKey, zeros(UInt8))
    end
end

function setBuffer!(ctx::AES256, buf::ASCIIString)
    if isfile(buf)
        file::IOStream = open("/home/student/Dokumenty/tes/main.cpp")
        content::ASCIIString=readall(file)
        close(file)
        ctx.buffer=Vector{UInt8}(content)
    else
        ctx.buffer=Vector{UInt8}(buf)
    end
end

f(x) = (((x)<<1) $ ((((x)>>7) & 1) * 0x1b))
fd(x) = (((x) >> 1) $ (((x) & 1) != 0 ? 0x8d : 0))
    
#calculate anti-logarithm gen 3
function gfALog(x::UInt8) 
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
function gfLog(x::UInt8) 
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
gfMulInv(x::UInt8) = (x != 0) ? gfALog(UInt8(255) - gfLog(x)) : 0 

function rjSbox(x::UInt8)
    local y::UInt8 = sb::UInt8 = gfMulInv(x)
    
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

function rjSboxInv(x::UInt8)
    local y::UInt8 = x $ 0x63
    local sb::UInt8 = y = (y<<1)|(y>>7)
    y = (y<<2)|(y>>6)
    sb $= y
    y = (y<<3)|(y>>5)
    sb $= y

    return gfMulInv(sb)
end
        
rjXTime(x::UInt8) = (x & 0x80) > 0 ? ((x << 1) $ 0x1b) : (x << 1)

function aesSubBytes!(buf::Array{UInt8})
    local i::UInt8 = 17
    while i > 1
        i -= 1
        buf[i] = rjSbox(buf[i])
    end
end

function aesSubBytesInv!(buf::Array{UInt8})
    local i::UInt8 = 17
    while i > 1
        i -= 1
        buf[i] = rjSboxInv(buf[i])
    end
end

function aesAddRoundKey!(buf::Array{UInt8}, key::AbstractArray{UInt8})
    local i::UInt8 = 17
    while i > 1
        i -= 1
        buf[i] $= key[i]
    end
end

function aesAddRoundKeyCpy!(buf::Array{UInt8}, key::Array{UInt8}, cpk::Array{UInt8})
    i::UInt8 = 17
    while i > 1
        i -= 1
        buf[i] $= (cpk[i] = key[i])
        cpk[16+i] = key[16 + i]
    end
end

function aesShiftRows!(buf::Array{UInt8})
    local i::UInt8 = 0
    local j::UInt8 = 0

    i = buf[1]; buf[1] = buf[5]; buf[5] = buf[9]; buf[9] = buf[13]; buf[13] = i;
    i = buf[10]; buf[10] = buf[2]; buf[2] = i;
    j = buf[3]; buf[3] = buf[15]; buf[15] = buf[11]; buf[11] = buf[7]; buf[7] = j
    j = buf[14]; buf[14] = buf[6]; buf[6]  = j;
end

function aesShiftRowsInv!(buf::Array{UInt8})
    local i::UInt8 = 0
    local j::UInt8 = 0

    i = buf[1]; buf[1] = buf[13]; buf[13] = buf[9]; buf[9] = buf[5]; buf[5] = i;
    i = buf[2]; buf[2] = buf[10]; buf[10] = i;
    j = buf[3]; buf[3] = buf[7]; buf[7] = buf[11]; buf[11] = buf[15]; buf[15] = j;
    j = buf[6]; buf[6] = buf[14]; buf[14] = j;
end

function aesMixColumns!(buf::Array{UInt8})
    local i::UInt8 = 0
    local a::UInt8 = 0
    local b::UInt8 = 0
    local c::UInt8 = 0
    local d::UInt8 = 0
    local e::UInt8 = 0
    
    for i in 1:4:16
        a = buf[i]; b = buf[i + 1]; c = buf[i + 2]; d = buf[i + 3];
        e = a $ b $ c $ d;
        buf[i] $= e $ rjXTime(a$b);   buf[i+1] $= e $ rjXTime(b$c);
        buf[i+2] $= e $ rjXTime(c$d); buf[i+3] $= e $ rjXTime(d$a);
    end
end

function aesMixColumnsInv!(buf::Array{UInt8})
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
        z = rjXTime(e);
        x = e $ rjXTime(rjXTime(z$a$c));  y = e $ rjXTime(rjXTime(z$b$d));
        buf[i] $= x $ rjXTime(a$b);   buf[i+1] $= y $ rjXTime(b$c);
        buf[i+2] $= x $ rjXTime(c$d); buf[i+3] $= y $ rjXTime(d$a);
    end
end

function aesExpandEncKey!(k::Array{UInt8}, rc::UInt8) 
    local i::UInt8 = 0

    k[1] $= rjSbox(k[30]) $ rc
    k[2] $= rjSbox(k[31])
    k[3] $= rjSbox(k[32])
    k[4] $= rjSbox(k[29])
    rc = f(rc)

    for i in 5:4:15
        k[i] $= k[i-4]
        k[i+1] $= k[i-3]
        k[i+2] $= k[i-2]
        k[i+3] $= k[i-1]
    end
    
    k[17] $= rjSbox(k[13])
    k[18] $= rjSbox(k[14])
    k[19] $= rjSbox(k[15])
    k[20] $= rjSbox(k[16])

    for i in 21:4:31
        k[i] $= k[i-4]
        k[i+1] $= k[i-3]
        k[i+2] $= k[i-2]
        k[i+3] $= k[i-1]
    end
    
    return rc
end

function aesExpandDecKey!(k::Array{UInt8}, rc::UInt8) 
    local i::UInt8 = 0
    
    for i in 29:-4:18
        k[i] $= k[i-4]
        k[i+1] $= k[i-3]
        k[i+2] $= k[i-2]
        k[i+3] $= k[i-1]
    end

    k[17] $= rjSbox(k[13])
    k[18] $= rjSbox(k[14])
    k[19] $= rjSbox(k[15])
    k[20] $= rjSbox(k[16])

    for i in 13:-4:5
        k[i] $= k[i-4]
        k[i+1] $= k[i-3]
        k[i+2] $= k[i-2]
        k[i+3] $= k[i-1]
    end

    rc = fd(rc);
    k[1] $= rjSbox(k[30]) $ rc
    k[2] $= rjSbox(k[31])
    k[3] $= rjSbox(k[32])
    k[4] $= rjSbox(k[29])
    
    return rc
end

#tests!!!!!!!
function AES256Done(ctx::AES256)
    i::UInt8 = 0
    
    for i in 1:1:length(ctx.key)
        ctx.key[i]=ctx.enckey[i]=ctx.deckey[i]=0
    end
end
#!!!!!!!!!!!!

function encrypt(buf::Array{UInt8}, key::Array{UInt8})
    local i::UInt8 = 1
    local rcon::UInt8 = 1
    
    aesAddRoundKeyCpy!(buf, key, key)
    for i in 1:1:13
        aesSubBytes!(buf)
        aesShiftRows!(buf)
        aesMixColumns!(buf)
        if (i & 1) > 0
            aesAddRoundKey!(buf, sub(key, 16:32))
        else 
            rcon = aesExpandEncKey!(key, rcon)
            aesAddRoundKey!(buf, key)
        end
    end
    aesSubBytes!(buf)
    aesShiftRows!(buf)
    aesExpandEncKey!(key, rcon)
    aesAddRoundKey!(buf, key)
end

function decrypt(buf::Array{UInt8}, key::Array{UInt8})
    local i::UInt8 = 13
    local rcon::UInt8 = 0x80

    aesAddRoundKeyCpy!(buf, key, key)
    aesShiftRowsInv!(buf)
    aesSubBytesInv!(buf)

    while i > 0
        if (i & 1) > 0
            rcon = aesExpandDecKey!(key, rcon)
            aesAddRoundKey!(buf, sub(key, 16:32))
        else 
            aesAddRoundKey!(buf, key)
        end
        aesMixColumnsInv!(buf)
        aesShiftRowsInv!(buf)
        aesSubBytesInv!(buf)
        i-=1
    end
    aesAddRoundKey!(buf, key)
end
        
#tests
function tests()
    assert(gfALog(UInt8(151)) == UInt8(192))
    assert(gfALog(UInt8(253)) == UInt8(82))

    assert(gfLog(UInt8(11)) == UInt8(104))
    assert(gfLog(UInt8(5)) == UInt8(2))

    assert(gfMulInv(UInt8(43)) == UInt8(21))
    assert(gfMulInv(UInt8(107)) == UInt8(223))

    assert(rjSbox(UInt8(0)) == UInt8(99))
    assert(rjSbox(UInt8(11)) == UInt8(43))

    assert(rjSboxInv(UInt8(105)) == UInt8(228))
    assert(rjSboxInv(UInt8(206)) == UInt8(236))

    assert(rjXTime(UInt8(232)) == UInt8(203))
    assert(rjXTime(UInt8(10)) == UInt8(20))

    #aesSubBytesInv
    testArrayAesSubBytesInv::Array{UInt8} = [187, 37, 63, 68, 233, 109, 200, 238, 123, 16, 177, 103, 99, 59, 206, 105]
    resultAesSubBytesInv::Array{UInt8} = [254, 194, 37, 134, 235, 179, 177, 153, 3, 124, 86, 10, 0, 73, 236, 228]
    aesSubBytesInv!(testArrayAesSubBytesInv)
    assert(length(setdiff(testArrayAesSubBytesInv,resultAesSubBytesInv)) == 0)
    #--------------#
    
    #aesAddRoundKey
    testAesAddRoundKeyBuf::Array{UInt8} = [254, 194, 37, 134, 235, 179, 177, 153, 3, 124, 86, 10, 0, 73, 236, 228]
    testAesAddRoundKeyKey::Array{UInt8} = [234, 228, 240, 137, 19, 203, 168, 178, 37, 100, 95,202, 60, 211, 47, 74, 105, 110, 102, 111, 114, 109, 97, 116, 121, 107, 97, 0, 0, 0, 0, 0]
    resultAesAddRoundKey::Array{UInt8} = [20, 38, 213, 15, 248, 120, 25, 43, 38, 24, 9, 192, 60, 154, 195, 174]
    aesAddRoundKey!(testAesAddRoundKeyBuf, testAesAddRoundKeyKey)
    assert(length(setdiff(testAesAddRoundKeyBuf,resultAesAddRoundKey)) == 0)
    #--------------#
    
    #aesAddRoundKeyCpy
    testAesAddRoundKeyCpyKey::Array{UInt8} = [125, 156, 95, 194, 59, 235, 124, 120, 142, 180, 241, 78, 134, 247, 56, 21, 174, 140, 247, 208, 189, 71, 95, 98, 152, 35, 0, 168, 164, 240, 47, 226]
    testAesAddRoundKeyCpyBuf::Array{UInt8} = [198, 241, 238, 171, 210, 251, 178, 60, 245, 143, 206, 160, 229, 210, 240, 114]
    testAesAddRoundKeyCpyCpk::Array{UInt8} = Array{UInt8}(32)
    resultAesAddRoundKeyCpy::Array{UInt8} = [187, 109, 177, 105, 233, 16, 206, 68, 123, 59, 63, 238, 99, 37, 200, 103]
    aesAddRoundKeyCpy!(testAesAddRoundKeyCpyBuf, testAesAddRoundKeyCpyKey, testAesAddRoundKeyCpyCpk)
    assert(length(setdiff(testAesAddRoundKeyCpyBuf,resultAesAddRoundKeyCpy)) == 0)
    assert(length(setdiff(testAesAddRoundKeyCpyKey,testAesAddRoundKeyCpyCpk)) == 0)
    #--------------#
    
    #aesShiftRowsInv
    testAesShiftRowsInv::Array{UInt8} = [187, 109, 177, 105, 233, 16, 206, 68, 123, 59, 63, 238, 99, 37, 200, 103]
    resultAesShiftRowsInv::Array{UInt8} = [187, 37, 63, 68, 233, 109, 200, 238, 123, 16, 177, 103, 99, 59, 206, 105]
    aesShiftRowsInv!(testAesShiftRowsInv)
    assert(length(setdiff(testAesShiftRowsInv,resultAesShiftRowsInv)) == 0)
    #--------------#
    
    #aesMixColumnsInv
    testAesMixColumnsInv::Array{UInt8} = [20, 38, 213, 15, 248, 120, 25, 43, 38, 24, 9, 192, 60, 154, 195, 174]
    resultAesMixColumnsInv::Array{UInt8} = [176, 150, 186, 116, 31, 184, 129, 148, 232, 121, 50, 84, 115, 49, 1, 136]
    aesMixColumnsInv!(testAesMixColumnsInv)
    assert(length(setdiff(testAesMixColumnsInv,resultAesMixColumnsInv)) == 0)
    #--------------#
    
    #aesExpandDecKey
    testAesExpandDecKey::Array{UInt8} = [125, 156, 95, 194, 59, 235, 124, 120, 142, 180, 241, 78, 134, 247, 56, 21, 174, 140, 247, 208, 189, 71, 95, 98, 152, 35, 0, 168, 164, 240, 47, 226]
    testrcAesExpandDecKey::UInt8 = 128
    resultAesExpandDecKey::Array{UInt8} = [91, 137, 137, 41, 70, 119, 35, 186, 181, 95, 141, 54, 8, 67, 201, 91, 234, 228, 240, 137, 19, 203, 168, 178, 37, 100, 95, 202, 60, 211, 47, 74]
    aesExpandDecKey!(testAesExpandDecKey, testrcAesExpandDecKey)
    assert(length(setdiff(testAesExpandDecKey,resultAesExpandDecKey)) == 0)
    #--------------#
    
    #aesSubBytes
    testAesSubBytes::Array{UInt8} = [206, 91, 202, 206, 76, 47, 217, 126, 131, 93, 59, 44, 25, 227, 44, 95]
    resultAesSubBytes::Array{UInt8} = [139, 57, 116, 139, 41, 21, 53, 243, 236, 76, 226, 113, 212, 17, 113, 207]
    aesSubBytes!(testAesSubBytes)
    assert(length(setdiff(testAesSubBytes,resultAesSubBytes)) == 0)
    #--------------#
    
    #aesShiftRows
    testAesShiftRows::Array{UInt8} = [192, 4, 69, 51, 129, 137, 236, 97, 155, 67, 77, 251, 232, 120, 190, 202]
    resultAesShiftRows::Array{UInt8} = [192, 137, 77, 202, 129, 67, 190, 51, 155, 120, 69, 97, 232, 4, 236, 251]
    aesShiftRows!(testAesShiftRows)
    assert(length(setdiff(testAesShiftRows,resultAesShiftRows)) == 0)
    #--------------#
    
    #aesMixColumns
    testAesMixColumns::Array{UInt8} = [34, 51, 89, 244, 117, 4, 107, 115, 190, 216, 168, 177, 152, 123, 150, 174]
    resultAesMixColumns::Array{UInt8} = [188, 91, 164, 255, 254, 179, 50, 22, 13, 71, 229, 208, 158, 97, 61, 25]
    aesMixColumns!(testAesMixColumns)
    assert(length(setdiff(testAesMixColumns,resultAesMixColumns)) == 0)
    #--------------#
    
    #aesExpandEncKey
    testAesExpandEncKey::Array{UInt8} = [105, 110, 102, 111, 114, 109, 97, 116, 121, 107, 97, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    testrcAesExpandEncKey::UInt8 = 1
    resultAesExpandEncKey::Array{UInt8} = [1, 11, 13, 5, 12, 121, 96, 100, 120, 0, 11, 5, 120, 0, 11, 5, 120, 99, 43, 107, 188, 99, 43, 107, 188, 99, 43, 107, 188, 99, 43, 107, 188]
    aesExpandEncKey!(testAesExpandEncKey, testrcAesExpandEncKey)
    assert(length(setdiff(testAesExpandEncKey,resultAesExpandEncKey)) == 0)
    #--------------#
    
    #type
    aesObj::AES256 = AES256("informatyka")
    resultAesObjEncKey::Array{UInt8}=[105, 110, 102, 111, 114, 109, 97, 116, 121, 107, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    resultAesObjDecKey::Array{UInt8}=[125, 156, 95, 194, 59, 235, 124, 120, 142, 180, 241, 78, 134, 247, 56, 21, 174, 140, 247, 208, 189, 71, 95, 98, 152, 35, 0, 168, 164, 240, 47, 226]
    resultAesObjKey::Array{UInt8}=zeros(UInt8, 32)
    assert(length(setdiff(aesObj.key,resultAesObjKey)) == 0)
    assert(length(setdiff(aesObj.enckey,resultAesObjEncKey)) == 0)
    assert(length(setdiff(aesObj.deckey,resultAesObjDecKey)) == 0)
    #--------
    
    #encrypt/decrypt
    encAesObj::AES256 = AES256("encrypting")
    fraze::ASCIIString = "encryptordecrypt"
    setBuffer!(encAesObj, fraze)
    encrypt(encAesObj.buffer, encAesObj.enckey)
    decrypt(encAesObj.buffer, encAesObj.deckey)
    assert(length(setdiff(encAesObj.buffer, Vector{UInt8}(fraze))) == 0)
    #--------
end
#endtests

tests()

end
