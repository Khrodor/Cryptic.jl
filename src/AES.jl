
module AES

export AES256

macro rj_sbox(idx::Int)
    const Sbox = reshape(
    [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, 
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]
    ,16,16)
    return :($Sbox[$idx])
end

macro rj_sbox_inv(idx::Int)
    const InvSbox = reshape(
    [0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D]
    ,16,16)
    return :($InvSbox[$idx])
end

type AES256
    key::Array{UInt8}
    enckey::Array{UInt8}
    deckey::Array{UInt8}
    
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
        new(Array{UInt8}(32), encKey, decKey)
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

function aesAddRoundKey!(buf::Array{UInt8}, key::Array{UInt8})
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

#tests!!!!!!!
function encrypt(buf::Array{UInt8}, key::Array{UInt8})
    local i::UInt8 = 1
    local rcon::UInt8 = 1
    
    aesAddRoundKeyCpy(buf, key, key)
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
#!!!!!!!!!!!!

#tests!!!!!!!
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
        i-=0
    end
    aesAddRoundKey!(buf, key)
end
#!!!!!!!!!!!!
        
#tests
function tests()
    
    assert(@rj_sbox(17) == 0xCA)
    assert(@rj_sbox_inv(114) == 0x2C)

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
    resultAesObjKey::Array{UInt8}=Array{UInt8}(32)
    assert(length(setdiff(aesObj.key,resultAesObjKey)) == 0)
    assert(length(setdiff(aesObj.enckey,resultAesObjEncKey)) == 0)
    assert(length(setdiff(aesObj.deckey,resultAesObjDecKey)) == 0)
    #--------
end
#endtests

tests()

end
