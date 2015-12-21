module Trivium

export trivium_stream, trivium_init


function trivium_stream( n::Int64, s::BitArray{1} )
    
    assert( length(s) == 288 )
 
    z = BitArray( n )
    
    for i in 1:n

        
        t1 = s[66] $ s[93]
        t2 = s[162] $ s[177]
        t3 = s[243] $ s[288]
        
        z[i] = t1 $ t2 $ t3
        
        t1 = t1 $ ( s[91] & s[92] ) $ s[171]
        t2 = t2 $ ( s[175] & s[176] ) $ s[264]
        t3 = t3 $ ( s[286] & s[287] ) $ s[69]
        
        s[2:93] = s[1:92] 
        s[1] = t3
        
        s[95:177] = s[94:176] 
        s[94] = t1

        s[179:288] = s[178:287] 
        s[178] = t2

    end
    
    z, s
end


function trivium_init( key::BitArray{1}, iv::BitArray{1})
   
    assert( length(key) == 80 )
    assert( length(iv) == 80 )
    
    s = BitArray(288)
    
    s[1:80] = key
    s[81:93] = bitpack( zeros(UInt8, 13) )
    
    s[94:173] = iv
    s[174:285] = bitpack( zeros(UInt8, 288 - 174 + 1 - 3) )
    
    s[ 286:288 ] = bitpack( ones(UInt8, 3) ) 
    
    for i in 1:(288 * 4)
        t1 = s[66] $ ( s[91] & s[92] ) $ s[93] $ s[171]
        t2 = s[162] $ ( s[175] & s[176] ) $ s[177] $ s[264]
        t3 = s[243] $ ( s[286] & s[287] ) $ s[288] $ s[69]
        
        s[2:93] = s[1:92] 
        s[1] = t3
        
        s[95:177] = s[94:176] 
        s[94] = t1
        
        s[179:288] = s[178:287] 
        s[178] = t2
        
    end
    
    s
end

#stt = bitpack( ones( UInt8, 288 )  )
#trivium_stream( BitArray(288), 5 )
#k = bitpack([ rand(0:1) for i in 1:80 ])
#ivv = bitpack([ rand(0:1) for i in 1:80 ])
#state = trivium_init( k, ivv )

#plain = [ rand(0:1) for i in 1:34560 ]
#stream, state = trivium_stream( state, length( plain ) )

#state


end
