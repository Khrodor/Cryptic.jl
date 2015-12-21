module Grain
export grain_stream, grain_init


function grain_updatelsfr( s::BitArray )
    u = s[63] $ s[52] $ s[39] $ s[24] $ s[14] 
    s >>= 1
    s[1] = u
    
    s
end

function grain_updatensfr( b::BitArray, si )
    u = b[63] $ b[61] $ b[53] $ b[46] $ b[38] $ b[34] $ b[29] $ b[22] $ b[15] $ b[10] $ (b[64] & b[61] ) $ ( b[38] & b[34] ) $ ( b[16] & b[10] ) $ ( b[61] & b[53] & b[46] ) $ (b[34] & b[29] & b[22] ) $ ( b[64] & b[46] & b[29] & b[10] ) $ ( b[61] & b[53] & b[38] & b[34] ) $ ( b[64] & b[61] & b[22] & b[16] )$ ( b[64] & b[61] & b[53] & b[46] & b[38] ) $ ( b[34] & b[29] & b[22] & b[16] & b[10] ) $ ( b[53] & b[46] & b[38] & b[34] & b[29] & b[22] )
    u $= si
    b >>= 1
    b[1] = u
    
    b
end

a = [1,2,4,10,31,43,56]
a += 1

function grainh( s::BitArray, b::BitArray )
    
    x0 = s[4]
    x1 = s[26]
    x2 = s[47]
    x3 = s[65]
    x4 = b[64]

    ret = x1 $ x4 $ (x0 & x3) $ ( x2 & x3 ) $ ( x3 & x4 ) $ ( x0 & x1 & x2 ) $ ( x0 & x2 & x3 ) $ ( x0 & x2 & x4 ) $ ( x1 & x2 & x4 ) $ ( x2 & x3 & x4 )
    
    ret
end

function grainzi( s::BitArray, b::BitArray )
    
    zi = false
    for k in a
        zi $= b[k] $ grainh( s, b )
    end

    zi
end

function grain_init( k::BitArray, iv::BitArray )
    
    assert( length(k) == 80 )
    assert( length(iv) == 64 )
    
    b = copy(k)
    
    s = BitArray(80)
    
    s[1:64] = iv
    s[65:80] = BitArray( ones(16) )
    
    for i in 1:160
        si = grainzi( s, b )
        s = grain_updatelsfr( s )
        b = grain_updatensfr( b, si )
    end
    
    (s, b)
end

function grain_stream( l, s::BitArray, b::BitArray )
    
    o = BitArray(l)
    
    for i in 1:l
        o[i]= grainzi( s, b )
        s = grain_updatelsfr( s )
        b = grain_updatensfr( b, o[i] )
    end

    (o, s, b)
end

#as_k = BitArray(80)
#as_iv = BitArray(64)
#for i in 1:length(as_k)
#    as_k[i] = round(rand())
#end
#for i in 1:length(as_iv)
#    as_iv[i] = round(rand())
#end

#as_s, as_b = grain_init( BitArray(80), BitArray(64) )
#as_o, as_s, as_b = grain_stream(1000, as_s, as_b)
#as_o



end
