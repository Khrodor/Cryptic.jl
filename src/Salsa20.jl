module Salsa20
export salsa20


function leftShift( w::UInt32, s::Int )
    ( w << s ) | ( w >> ( 32 - s) ) 
end

function quarterround( y::Array{UInt32} )
    z = Array{UInt32}(4)
    
    z[2] = y[2] $ ( leftShift( y[1] + y[4], 7) )
    z[3] = y[3] $ ( leftShift( z[2] + y[1], 9) )
    z[4] = y[4] $ ( leftShift( z[3] + z[2], 13) )
    z[1] = y[1] $ ( leftShift( z[4] + z[3], 18) )
    
    z
end

function rowround( y::Array{UInt32} )
    z = Array{UInt32}(16)
    
    z[ [1,2,3,4] ] = quarterround( y[ [1,2,3,4] ] )
    z[ [6,7,8,5] ] = quarterround( y[ [6,7,8,5] ] )
    z[ [11,12,9,10] ] = quarterround( y[ [11,12,9,10] ] )
    z[ [16,13,14,15] ] = quarterround( y[ [16,13,14,15] ] )
    
    z
end

function columnround( y::Array{UInt32} )
    z = Array{UInt32}(16)
    
    z[ [1,5,9,13,2,6,10,14,3,7,11,15,4,8,12,16] ] = rowround( y[ [1,5,9,13,2,6,10,14,3,7,11,15,4,8,12,16] ] )
    
    z
end

function doubleround( y::Array{UInt32} )
    z = Array{UInt32}(16)
    
    rowround( columnround(y) )
end

function littleendian( b::Array{UInt8} )
    z::UInt32
    
    z = UInt32( b[1] ) | ( UInt32( b[2] ) << 8 ) | ( UInt32( b[3] ) << 16 ) | ( UInt32( b[4] ) << 24 )
end

function littleendianinv( w::UInt32 )
    z = Array{UInt8}(4)
    
    z[ 1 ] = (w & (0x000000ff << 0 ) ) >> 0
    z[ 2 ] = (w & (0x000000ff << 8 ) ) >> 8
    z[ 3 ] = (w & (0x000000ff << 16 ) ) >> 16
    z[ 4 ] = (w & (0x000000ff << 24 ) ) >> 24
    
    z
end

function salsa20hash( y::Array{UInt8} )
    r = Array{UInt8}(64)
    x = Array{UInt32}(16)
    z = Array{UInt32}(16)
    
    for i in 0:15
        x[ i + 1 ] = littleendian( y[(i*4 + 1):(i*4+4)] )
    end
    
    z = x
    for i in 1:10
        z = doubleround( z ) 
        end
    
    for i in 0:15
        r[ (i*4+1):(i*4+4) ] = littleendianinv( z[i+1] + x[i+1] ) 
    end
    
    r
end

function salsa20expansion( n::Array{UInt8}, k0::Array{UInt8}, k1::Array{UInt8} )
    p0 = [ UInt8(101), UInt8(120), UInt8(112), UInt8(97) ]
    p1 = [ UInt8(110), UInt8(100), UInt8(32), UInt8(51) ]
    p2 = [ UInt8(50), UInt8(45), UInt8(98), UInt8(121) ]
    p3 = [ UInt8(116), UInt8(101), UInt8(32), UInt8(107) ]
    
    data = Array{UInt8}(64)
    data[1:4] = p0
    data[5:20] = k0[1:16]
    data[21:24] = p1
    data[25:40] = n[1:16]
    data[41:44] = p2
    data[45:60] = k1[1:16]
    data[61:64] = p3
    
    salsa20hash( data )
    
end

function salsa20expansion( n::Array{UInt8}, k::Array{UInt8} )
    p0 = [ UInt8(101), UInt8(120), UInt8(112), UInt8(97) ]
    p1 = [ UInt8(110), UInt8(100), UInt8(32), UInt8(49) ]
    p2 = [ UInt8(54), UInt8(45), UInt8(98), UInt8(121) ]
    p3 = [ UInt8(116), UInt8(101), UInt8(32), UInt8(107) ]
    
    data = Array{UInt8}(64)
    data[1:4] = p0
    data[5:20] = k[1:16]
    data[21:24] = p1
    data[25:40] = n[1:16]
    data[41:44] = p2
    data[45:60] = k[1:16]
    data[61:64] = p3
    
    # p0, k, p1, n, p2, k, p3
    salsa20hash( data )
    
end

function salsa20( k::Array{UInt8}, v::Array{UInt8}, m::Array{UInt8} )

    l = Array{UInt8}( length(m) )
    iArray = Array{UInt8}(16) #iArray is 8 bytes + 8 to append
    
    sizeWithoutLast = UInt64( div( UInt64(length(m)), UInt64(64)) )
    sizeLast = UInt64( UInt64( length(m) ) % UInt64(64) )
   
    i = UInt64(0)
    idx = UInt64(0)
    while i < sizeWithoutLast
        iArray[1:8] = reinterpret( UInt8, [UInt64(i)] )
        iArray[9:16] = v[1:8]
        
        salsa = salsa20expansion( iArray, k )
        
        l[ (idx+1):(idx+64) ] = salsa[1:64] $ m[ (idx+1):(idx+64) ]
        
        idx += UInt64(64) 
        i += UInt64(1)
    end
    
    iArray[1:8] = reinterpret( UInt8, [UInt64(i)] )
    iArray[9:16] = v[1:8]
        
    salsa = salsa20expansion( iArray, k )
        
    l[ (idx+1):(idx+sizeLast) ] = salsa[1:sizeLast] $ m[ (idx+1):(idx+sizeLast) ]

    l
    
end

function salsa20( k0::Array{UInt8}, k1::Array{UInt8}, v::Array{UInt8}, m::Array{UInt8} )

    l = Array{UInt8}( length(m) )
    iArray = Array{UInt8}(16) #iArray is 8 bytes + 8 to append
    
    sizeWithoutLast = UInt64( div( UInt64(length(m)), UInt64(64)) )
    sizeLast = UInt64( UInt64( length(m) ) % UInt64(64) )
   
    i = UInt64(0)
    idx = UInt64(0)
    while i < sizeWithoutLast
        iArray[1:8] = reinterpret( UInt8, [UInt64(i)] )
        iArray[9:16] = v[1:8]
        
        salsa = salsa20expansion( iArray, k0, k1 )
        
        l[ (idx+1):(idx+64) ] = salsa[1:64] $ m[ (idx+1):(idx+64) ]
        
        idx += UInt64(64) 
        i += UInt64(1)
    end
    
    iArray[1:8] = reinterpret( UInt8, [UInt64(i)] )
    iArray[9:16] = v[1:8]
        
    salsa = salsa20expansion( iArray, k0, k1 )
        
    l[ (idx+1):(idx+sizeLast) ] = salsa[1:sizeLast] $ m[ (idx+1):(idx+sizeLast) ]

    l
    
end

function salsaSelftest()
	for attempts in 1:10
	    assert_key = [UInt8(rand(0:255)) for i in 1:16]
	    assert_nonce = [UInt8(rand(0:255)) for i in 1:8]
	    assert_plain = [UInt8(rand(0:255)) for i in 1:rand(0:1000)]
	    assert_ciph = salsa20( assert_key, assert_nonce, assert_plain )
	    assert_replain = salsa20( assert_key, assert_nonce, assert_ciph )
	    assert( assert_plain == assert_replain )
	end

	for attempts in 1:10
	    assert_key0 = [UInt8(rand(0:255)) for i in 1:16]
	    assert_key1 = [UInt8(rand(0:255)) for i in 1:16]
	    assert_nonce = [UInt8(rand(0:255)) for i in 1:8]
	    assert_plain = [UInt8(rand(0:255)) for i in 1:rand(0:1000)]
	    assert_ciph = salsa20( assert_key0, assert_key1, assert_nonce, assert_plain )
	    assert_replain = salsa20( assert_key0, assert_key1, assert_nonce, assert_ciph )
	    assert( assert_plain == assert_replain )
	end

	#check leftShift funtion
	assert( leftShift( 0xc0a8787e, 5) == 0x150f0fd8 )

	#check quarterround function
	assert( quarterround([ 0x00000000 , 0x00000000 , 0x00000000 , 0x00000000 ]) == ([ 0x00000000 , 0x00000000 , 0x00000000 , 0x00000000 ]) )
	assert( quarterround([ 0x00000001 , 0x00000000 , 0x00000000 , 0x00000000 ]) == ([ 0x08008145 , 0x00000080 , 0x00010200 , 0x20500000 ]) )
	assert( quarterround([ 0x00000000 , 0x00000001 , 0x00000000 , 0x00000000 ]) == ([ 0x88000100 , 0x00000001 , 0x00000200 , 0x00402000 ]) )
	assert( quarterround([ 0x00000000 , 0x00000000 , 0x00000001 , 0x00000000 ]) == ([ 0x80040000 , 0x00000000 , 0x00000001 , 0x00002000 ]) )
	assert( quarterround([ 0x00000000 , 0x00000000 , 0x00000000 , 0x00000001 ]) == ([ 0x00048044 , 0x00000080 , 0x00010000 , 0x20100001 ]) )
	assert( quarterround([ 0xe7e8c006 , 0xc4f9417d , 0x6479b4b2 , 0x68c67137 ]) == ([ 0xe876d72b , 0x9361dfd5 , 0xf1460244 , 0x948541a3 ]) )
	assert( quarterround([ 0xd3917c5b , 0x55f1c407 , 0x52a58a7a , 0x8f887a3b ]) == ([ 0x3e2f308c , 0xd90a8f36 , 0x6ab2a923 , 0x2883524c ]) )

	#check rowround  function
	assert( rowround([ 0x00000001 , 0x00000000 , 0x00000000 , 0x00000000 , 0x00000001 , 0x00000000 , 0x00000000 , 0x00000000 , 0x00000001 , 0x00000000 , 0x00000000 , 0x00000000 , 0x00000001 , 0x00000000 , 0x00000000 , 0x00000000 ]) == ([ 0x08008145 , 0x00000080 , 0x00010200 , 0x20500000 , 0x20100001 , 0x00048044 , 0x00000080 , 0x00010000 , 0x00000001 , 0x00002000 , 0x80040000 , 0x00000000 , 0x00000001 , 0x00000200 , 0x00402000 , 0x88000100 ]) )
	assert( rowround([ 0x08521bd6 , 0x1fe88837 , 0xbb2aa576 , 0x3aa26365 , 0xc54c6a5b , 0x2fc74c2f , 0x6dd39cc3 , 0xda0a64f6 , 0x90a2f23d , 0x067f95a6 , 0x06b35f61 , 0x41e4732e , 0xe859c100 , 0xea4d84b7 , 0x0f619bff , 0xbc6e965a ]) == ([ 0xa890d39d , 0x65d71596 , 0xe9487daa , 0xc8ca6a86 , 0x949d2192 , 0x764b7754 , 0xe408d9b9 , 0x7a41b4d1 , 0x3402e183 , 0x3c3af432 , 0x50669f96 , 0xd89ef0a8 , 0x0040ede5 , 0xb545fbce , 0xd257ed4f , 0x1818882d ]) )

	#check columnround function
	assert( columnround([ 0x00000001 , 0x00000000 , 0x00000000 , 0x00000000 , 0x00000001 , 0x00000000 , 0x00000000 , 0x00000000 , 0x00000001 , 0x00000000 , 0x00000000 , 0x00000000 , 0x00000001 , 0x00000000 , 0x00000000 , 0x00000000 ]) == ([ 0x10090288 , 0x00000000 , 0x00000000 , 0x00000000 , 0x00000101 , 0x00000000 , 0x00000000 , 0x00000000 , 0x00020401 , 0x00000000 , 0x00000000 , 0x00000000 , 0x40a04001 , 0x00000000 , 0x00000000 , 0x00000000 ]) )
	assert( columnround([ 0x08521bd6 , 0x1fe88837 , 0xbb2aa576 , 0x3aa26365 , 0xc54c6a5b , 0x2fc74c2f , 0x6dd39cc3 , 0xda0a64f6 , 0x90a2f23d , 0x067f95a6 , 0x06b35f61 , 0x41e4732e , 0xe859c100 , 0xea4d84b7 , 0x0f619bff , 0xbc6e965a ]) == ([ 0x8c9d190a , 0xce8e4c90 , 0x1ef8e9d3 , 0x1326a71a , 0x90a20123 , 0xead3c4f3 , 0x63a091a0 , 0xf0708d69 , 0x789b010c , 0xd195a681 , 0xeb7d5504 , 0xa774135c , 0x481c2027 , 0x53a8e4b5 , 0x4c1f89c5 , 0x3f78c9c8 ]) )

	#check doublerand function
	assert( doubleround([ 0x00000001 , 0x00000000 , 0x00000000 , 0x00000000 , 0x00000000 , 0x00000000 , 0x00000000 , 0x00000000 , 0x00000000 , 0x00000000 , 0x00000000 , 0x00000000 , 0x00000000 , 0x00000000 , 0x00000000 , 0x00000000 ]) == ([ 0x8186a22d , 0x0040a284 , 0x82479210 , 0x06929051 , 0x08000090 , 0x02402200 , 0x00004000 , 0x00800000 , 0x00010200 , 0x20400000 , 0x08008104 , 0x00000000 , 0x20500000 , 0xa0000040 , 0x0008180a , 0x612a8020 ]) )
	assert( doubleround([ 0xde501066 , 0x6f9eb8f7 , 0xe4fbbd9b , 0x454e3f57 , 0xb75540d3 , 0x43e93a4c , 0x3a6f2aa0 , 0x726d6b36 , 0x9243f484 , 0x9145d1e8 , 0x4fa9d247 , 0xdc8dee11 , 0x054bf545 , 0x254dd653 , 0xd9421b6d , 0x67b276c1 ]) == ([ 0xccaaf672 , 0x23d960f7 , 0x9153e63a , 0xcd9a60d0 , 0x50440492 , 0xf07cad19 , 0xae344aa0 , 0xdf4cfdfc , 0xca531c29 , 0x8e7943db , 0xac1680cd , 0xd503ca00 , 0xa74b2ad6 , 0xbc331c5c , 0x1dda24c7 , 0xee928277 ]) )

	#check littleendian
	assert( littleendian([ UInt8(0) , UInt8(0) , UInt8(0) , UInt8(0)]) == 0x00000000 )
	assert( littleendian([ UInt8(86) , UInt8(75) , UInt8(30) , UInt8(9) ]) == 0x091e4b56 )
	assert( littleendian([ UInt8(255) , UInt8(255) , UInt8(255) , UInt8(250)]) == 0xfaffffff )

	#check littleendianinv
	assertArray = [ UInt8(0) , UInt8(0) , UInt8(0) , UInt8(0)]
	assert( littleendianinv( littleendian( assertArray ) ) == assertArray )
	assertArray = [ UInt8(86) , UInt8(75) , UInt8(30) , UInt8(9) ]
	assert( littleendianinv( littleendian( assertArray ) ) == assertArray )
	assertArray = [ UInt8(255) , UInt8(255) , UInt8(255) , UInt8(250)]
	assert( littleendianinv( littleendian( assertArray ) ) == assertArray )

	#check salsa20hash

	assert( salsa20hash( [UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ) ]) == ([UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 ), UInt8( 0 )]) )
	assert( salsa20hash([ UInt8( 211 ), UInt8( 159 ), UInt8( 13 ), UInt8( 115 ), UInt8( 76 ), UInt8( 55 ), UInt8( 82 ), UInt8( 183 ), UInt8( 3 ), UInt8( 117 ), UInt8( 222 ), UInt8( 37 ), UInt8( 191 ), UInt8( 187 ), UInt8( 234 ), UInt8( 136 ), UInt8( 49 ), UInt8( 237 ), UInt8( 179 ), UInt8( 48 ), UInt8( 1 ), UInt8( 106 ), UInt8( 178 ), UInt8( 219 ), UInt8( 175 ), UInt8( 199 ), UInt8( 166 ), UInt8( 48 ), UInt8( 86 ), UInt8( 16 ), UInt8( 179 ), UInt8( 207 ), UInt8( 31 ), UInt8( 240 ), UInt8( 32 ), UInt8( 63 ), UInt8( 15 ), UInt8( 83 ), UInt8( 93 ), UInt8( 161 ), UInt8( 116 ), UInt8( 147 ), UInt8( 48 ), UInt8( 113 ), UInt8( 238 ), UInt8( 55 ), UInt8( 204 ), UInt8( 36 ), UInt8( 79 ), UInt8( 201 ), UInt8( 235 ), UInt8( 79 ), UInt8( 3 ), UInt8( 81 ), UInt8( 156 ), UInt8( 47 ), UInt8( 203 ), UInt8( 26 ), UInt8( 244 ), UInt8( 243 ), UInt8( 88 ), UInt8( 118 ), UInt8( 104 ), UInt8( 54)]) == ([UInt8( 109 ), UInt8( 42 ), UInt8( 178 ), UInt8( 168 ), UInt8( 156 ), UInt8( 240 ), UInt8( 248 ), UInt8( 238 ), UInt8( 168 ), UInt8( 196 ), UInt8( 190 ), UInt8( 203 ), UInt8( 26 ), UInt8( 110 ), UInt8( 170 ), UInt8( 154 ), UInt8( 29 ), UInt8( 29 ), UInt8( 150 ), UInt8( 26 ), UInt8( 150 ), UInt8( 30 ), UInt8( 235 ), UInt8( 249 ), UInt8( 190 ), UInt8( 163 ), UInt8( 251 ), UInt8( 48 ), UInt8( 69 ), UInt8( 144 ), UInt8( 51 ), UInt8( 57 ), UInt8( 118 ), UInt8( 40 ), UInt8( 152 ), UInt8( 157 ), UInt8( 180 ), UInt8( 57 ), UInt8( 27 ), UInt8( 94 ), UInt8( 107 ), UInt8( 42 ), UInt8( 236 ), UInt8( 35 ), UInt8( 27 ), UInt8( 111 ), UInt8( 114 ), UInt8( 114 ), UInt8( 219 ), UInt8( 236 ), UInt8( 232 ), UInt8( 135 ), UInt8( 111 ), UInt8( 155 ), UInt8( 110 ), UInt8( 18 ), UInt8( 24 ), UInt8( 232 ), UInt8( 95 ), UInt8( 158 ), UInt8( 179 ), UInt8( 19 ), UInt8( 48 ), UInt8( 202) ]) )
	assert( salsa20hash([ UInt8( 88 ), UInt8( 118 ), UInt8( 104 ), UInt8( 54 ), UInt8( 79 ), UInt8( 201 ), UInt8( 235 ), UInt8( 79 ), UInt8( 3 ), UInt8( 81 ), UInt8( 156 ), UInt8( 47 ), UInt8( 203 ), UInt8( 26 ), UInt8( 244 ), UInt8( 243 ), UInt8( 191 ), UInt8( 187 ), UInt8( 234 ), UInt8( 136 ), UInt8( 211 ), UInt8( 159 ), UInt8( 13 ), UInt8( 115 ), UInt8( 76 ), UInt8( 55 ), UInt8( 82 ), UInt8( 183 ), UInt8( 3 ), UInt8( 117 ), UInt8( 222 ), UInt8( 37 ), UInt8( 86 ), UInt8( 16 ), UInt8( 179 ), UInt8( 207 ), UInt8( 49 ), UInt8( 237 ), UInt8( 179 ), UInt8( 48 ), UInt8( 1 ), UInt8( 106 ), UInt8( 178 ), UInt8( 219 ), UInt8( 175 ), UInt8( 199 ), UInt8( 166 ), UInt8( 48 ), UInt8( 238 ), UInt8( 55 ), UInt8( 204 ), UInt8( 36 ), UInt8( 31 ), UInt8( 240 ), UInt8( 32 ), UInt8( 63 ), UInt8( 15 ), UInt8( 83 ), UInt8( 93 ), UInt8( 161 ), UInt8( 116 ), UInt8( 147 ), UInt8( 48 ), UInt8( 113)]) == ([UInt8( 179 ), UInt8( 19 ), UInt8( 48 ), UInt8( 202 ), UInt8( 219 ), UInt8( 236 ), UInt8( 232 ), UInt8( 135 ), UInt8( 111 ), UInt8( 155 ), UInt8( 110 ), UInt8( 18 ), UInt8( 24 ), UInt8( 232 ), UInt8( 95 ), UInt8( 158 ), UInt8( 26 ), UInt8( 110 ), UInt8( 170 ), UInt8( 154 ), UInt8( 109 ), UInt8( 42 ), UInt8( 178 ), UInt8( 168 ), UInt8( 156 ), UInt8( 240 ), UInt8( 248 ), UInt8( 238 ), UInt8( 168 ), UInt8( 196 ), UInt8( 190 ), UInt8( 203 ), UInt8( 69 ), UInt8( 144 ), UInt8( 51 ), UInt8( 57 ), UInt8( 29 ), UInt8( 29 ), UInt8( 150 ), UInt8( 26 ), UInt8( 150 ), UInt8( 30 ), UInt8( 235 ), UInt8( 249 ), UInt8( 190 ), UInt8( 163 ), UInt8( 251 ), UInt8( 48 ), UInt8( 27 ), UInt8( 111 ), UInt8( 114 ), UInt8( 114 ), UInt8( 118 ), UInt8( 40 ), UInt8( 152 ), UInt8( 157 ), UInt8( 180 ), UInt8( 57 ), UInt8( 27 ), UInt8( 94 ), UInt8( 107 ), UInt8( 42 ), UInt8( 236 ), UInt8( 35)]) )

	assertArray = [UInt8( 6 ), UInt8( 124 ), UInt8( 83 ), UInt8( 146 ), UInt8( 38 ), UInt8( 191 ), UInt8( 9 ), UInt8( 50 ), UInt8( 4 ), UInt8( 161 ), UInt8( 47 ), UInt8( 222 ), UInt8( 122 ), UInt8( 182 ), UInt8( 223 ), UInt8( 185 ), UInt8( 75 ), UInt8( 27 ), UInt8( 0 ), UInt8( 216 ), UInt8( 16 ), UInt8( 122 ), UInt8( 7 ), UInt8( 89 ), UInt8( 162 ), UInt8( 104 ), UInt8( 101 ), UInt8( 147 ), UInt8( 213 ), UInt8( 21 ), UInt8( 54 ), UInt8( 95 ), UInt8( 225 ), UInt8( 253 ), UInt8( 139 ), UInt8( 176 ), UInt8( 105 ), UInt8( 132 ), UInt8( 23 ), UInt8( 116 ), UInt8( 76 ), UInt8( 41 ), UInt8( 176 ), UInt8( 207 ), UInt8( 221 ), UInt8( 34 ), UInt8( 157 ), UInt8( 108 ), UInt8( 94 ), UInt8( 94 ), UInt8( 99 ), UInt8( 52 ), UInt8( 90 ), UInt8( 117 ), UInt8( 91 ), UInt8( 220 ), UInt8( 146 ), UInt8( 190 ), UInt8( 239 ), UInt8( 143 ), UInt8( 196 ), UInt8( 176 ), UInt8( 130 ), UInt8( 186) ]
	for i in 1:1000000
	    assertArray = salsa20hash( assertArray )
	end
	assert( assertArray == ([UInt8( 8 ), UInt8( 18 ), UInt8( 38 ), UInt8( 199 ), UInt8( 119 ), UInt8( 76 ), UInt8( 215 ), UInt8( 67 ), UInt8( 173 ), UInt8( 127 ), UInt8( 144 ), UInt8( 162 ), UInt8( 103 ), UInt8( 212 ), UInt8( 176 ), UInt8( 217 ), UInt8( 192 ), UInt8( 19 ), UInt8( 233 ), UInt8( 33 ), UInt8( 159 ), UInt8( 197 ), UInt8( 154 ), UInt8( 160 ), UInt8( 128 ), UInt8( 243 ), UInt8( 219 ), UInt8( 65 ), UInt8( 171 ), UInt8( 136 ), UInt8( 135 ), UInt8( 225 ), UInt8( 123 ), UInt8( 11 ), UInt8( 68 ), UInt8( 86 ), UInt8( 237 ), UInt8( 82 ), UInt8( 20 ), UInt8( 155 ), UInt8( 133 ), UInt8( 189 ), UInt8( 9 ), UInt8( 83 ), UInt8( 167 ), UInt8( 116 ), UInt8( 194 ), UInt8( 78 ), UInt8( 122 ), UInt8( 127 ), UInt8( 195 ), UInt8( 185 ), UInt8( 185 ), UInt8( 204 ), UInt8( 188 ), UInt8( 90 ), UInt8( 245 ), UInt8( 9 ), UInt8( 183 ), UInt8( 248 ), UInt8( 226 ), UInt8( 85 ), UInt8( 245 ), UInt8( 104)]) )

	#check salsa20expansion
	assert_k0 = [ UInt8(i) for i in 1:16 ]
	assert_k1 = [ UInt8(i) for i in 201:216 ]
	assert_n = [ UInt8(i) for i in 101:116 ]
	assert( salsa20expansion( assert_n, assert_k0 ) == ([UInt8( 39 ), UInt8( 173 ), UInt8( 46 ), UInt8( 248 ), UInt8( 30 ), UInt8( 200 ), UInt8( 82 ), UInt8( 17 ), UInt8( 48 ), UInt8( 67 ), UInt8( 254 ), UInt8( 239 ), UInt8( 37 ), UInt8( 18 ), UInt8( 13 ), UInt8( 247 ), UInt8( 241 ), UInt8( 200 ), UInt8( 61 ), UInt8( 144 ), UInt8( 10 ), UInt8( 55 ), UInt8( 50 ), UInt8( 185 ), UInt8( 6 ), UInt8( 47 ), UInt8( 246 ), UInt8( 253 ), UInt8( 143 ), UInt8( 86 ), UInt8( 187 ), UInt8( 225 ), UInt8( 134 ), UInt8( 85 ), UInt8( 110 ), UInt8( 246 ), UInt8( 161 ), UInt8( 163 ), UInt8( 43 ), UInt8( 235 ), UInt8( 231 ), UInt8( 94 ), UInt8( 171 ), UInt8( 51 ), UInt8( 145 ), UInt8( 214 ), UInt8( 112 ), UInt8( 29 ), UInt8( 14 ), UInt8( 232 ), UInt8( 5 ), UInt8( 16 ), UInt8( 151 ), UInt8( 140 ), UInt8( 183 ), UInt8( 141 ), UInt8( 171 ), UInt8( 9 ), UInt8( 122 ), UInt8( 181 ), UInt8( 104 ), UInt8( 182 ), UInt8( 177 ), UInt8( 193) ] ))
	assert( salsa20expansion( assert_n, assert_k0, assert_k1) ==  ([UInt8( 69 ), UInt8( 37 ), UInt8( 68 ), UInt8( 39 ), UInt8( 41 ), UInt8( 15 ), UInt8( 107 ), UInt8( 193 ), UInt8( 255 ), UInt8( 139 ), UInt8( 122 ), UInt8( 6 ), UInt8( 170 ), UInt8( 233 ), UInt8( 217 ), UInt8( 98 ), UInt8( 89 ), UInt8( 144 ), UInt8( 182 ), UInt8( 106 ), UInt8( 21 ), UInt8( 51 ), UInt8( 200 ), UInt8( 65 ), UInt8( 239 ), UInt8( 49 ), UInt8( 222 ), UInt8( 34 ), UInt8( 215 ), UInt8( 114 ), UInt8( 40 ), UInt8( 126 ), UInt8( 104 ), UInt8( 197 ), UInt8( 7 ), UInt8( 225 ), UInt8( 197 ), UInt8( 153 ), UInt8( 31 ), UInt8( 2 ), UInt8( 102 ), UInt8( 78 ), UInt8( 76 ), UInt8( 176 ), UInt8( 84 ), UInt8( 245 ), UInt8( 246 ), UInt8( 184 ), UInt8( 177 ), UInt8( 160 ), UInt8( 133 ), UInt8( 130 ), UInt8( 6 ), UInt8( 72 ), UInt8( 149 ), UInt8( 119 ), UInt8( 192 ), UInt8( 195 ), UInt8( 132 ), UInt8( 236 ), UInt8( 234 ), UInt8( 103 ), UInt8( 246 ), UInt8( 74) ]) )

	#verify encryption and decryption
	for attempts in 1:10
	    assert_key = [UInt8(rand(0:255)) for i in 1:16]
	    assert_nonce = [UInt8(rand(0:255)) for i in 1:8]
	    assert_plain = [UInt8(rand(0:255)) for i in 1:rand(0:1000)]
	    assert_ciph = salsa20( assert_key, assert_nonce, assert_plain )
	    assert_replain = salsa20( assert_key, assert_nonce, assert_ciph )
	    assert( assert_plain == assert_replain )
	end

	for attempts in 1:10
	    assert_key0 = [UInt8(rand(0:255)) for i in 1:16]
	    assert_key1 = [UInt8(rand(0:255)) for i in 1:16]
	    assert_nonce = [UInt8(rand(0:255)) for i in 1:8]
	    assert_plain = [UInt8(rand(0:255)) for i in 1:rand(0:1000)]
	    assert_ciph = salsa20( assert_key0, assert_key1, assert_nonce, assert_plain )
	    assert_replain = salsa20( assert_key0, assert_key1, assert_nonce, assert_ciph )
	    assert( assert_plain == assert_replain )
	end

	#@profile( for i in 1:10; salsa20( assert_key, assert_nonce, assert_plain ); end )

end

end
