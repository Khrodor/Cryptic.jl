module Mickey
export mickey_stream, mickey_init

rtaps = [97,96,95,94,92,91,90,89,88,87,82,81,80,79,72,71,67,66,65,64,63,61,60,58,56,54,52,50,46,45,42,41,38,37,28,25,22,21,20,19,16,13,12,9,6,5,4,3,1,0]
rtaps += 1

comp0 = BitArray([0,0,0,1,1,0,0,0,1,0,1,1,1,1,0,1,0,0,1,0,1,0,1,1,0,0,1,0,1,1,0,1,0,0,1,0,0,0,0,0,0,0,1,0,1,0,1,0,1,0,0,0,0,1,0,1,0,0,1,1,1,1,0,0,1,0,1,0,1,1,1,1,1,1,1,1,1,0,1,0,1,1,1,1,1,1,0,1,0,1,0,0,0,0,0,0,1,1,])
comp1 = BitArray([1,0,1,1,0,0,1,0,1,1,1,1,0,0,1,0,1,0,0,0,1,1,0,1,0,1,1,1,0,1,1,1,1,0,0,0,1,1,0,1,0,1,1,1,0,0,0,0,1,0,0,0,1,0,1,1,1,0,0,0,1,1,1,1,1,1,0,1,0,1,1,1,0,1,1,1,1,0,0,0,1,0,0,0,0,1,1,1,0,0,0,1,0,0,1,1,0,0 ])
fb0 = BitArray([1,1,1,1,0,1,0,1,1,1,1,1,1,1,1,0,0,1,0,1,1,1,1,1,1,1,1,1,1,0,0,1,1,0,0,0,0,0,0,1,1,1,0,0,1,0,0,1,0,1,0,1,0,0,1,0,1,1,1,1,0,1,0,1,0,1,0,0,0,0,0,0,0,0,0,1,1,0,1,0,0,0,1,1,0,1,1,1,0,0,1,1,1,0,0,1,1,0,0,0])
fb1 = BitArray([1,1,1,0,1,1,1,0,0,0,0,1,1,1,0,1,0,0,1,1,0,0,0,1,0,0,1,1,0,0,1,0,1,1,0,0,0,1,1,0,0,0,0,0,1,1,0,1,1,0,0,0,1,0,0,0,1,0,0,1,0,0,1,0,1,1,0,1,0,1,0,0,1,0,1,0,0,0,1,1,1,1,0,1,1,1,1,1,0,0,0,0,0,0,1,0,0,0,0,1])

function mickey_clock_r( r::BitArray, ibr, cbr )
    
    assert( length(r) == 100 )
    
    rp = copy(r)
    
    fb = r[100] $ ibr
    
    rp >>= 1
    
    for i in rtaps
        rp[i] $= fb0[i]
    end
    
    if cbr
        rp $= r
    end
      
    rp
end

function mickey_clock_s( s::BitArray, ibs, cbs )
   
    sp = copy(s)
    sh = copy(s)
    
    fb = s[100] $ ibs
    
    for i in 1:98
        sh[ i + 1 ] = s[i] $ ( ( s[i+1] $ comp0[i] ) & ( s[i+2] & comp1[i]) ) 
    end
    
    sh[1] = false
    sh[100] = s[99]
    
    if ! cbs
        sp = sh $ ( fb0 & fb )
    end
    
    if cbs
        sp = sh $ ( fb1 & fb )
    end
    
    sp
end

function mickey_clock_kg( r::BitArray, s::BitArray, mixing, ib )
    
    cbr = s[35] & r[68]
    cbs = s[68] & r[34]
    
    ibr
    if mixing
        ibr = ib $ (s[51]) 
    else
        ibr = ib
    end
    
    ibs = ib
    
    r = mickey_clock_r( r, ibs, cbr )
    s = mickey_clock_s( s, ibs, cbs )
    
    r, s
    
end

function mickey_init( iv::BitArray, k::BitArray)
   
    assert( length(k) == 80 )
    assert( length(iv) == 80 )
    
    r = BitArray(100)
    s = BitArray(100)
    
    for i in 1:100
        r[i] = 0
        s[i] = 0
    end
    
    for i in 0:(length(iv)-1)
        r, s = mickey_clock_kg( r, s, true, iv[i+1] ) 
    end
    
    for i in 0:79
        r, s = mickey_clock_kg(r, s, true, k[i+1]) 
    end
    
    for i in 0:99
        r, s = mickey_clock_kg(r, s, true, false) 
    end
    
    r, s
end

function mickey_stream( l::Int, r::BitArray, s::BitArray )
    
    assert( l >= 0)
    
    z = BitArray( l )
    
    for i in 1:l
        z[i] = r[1] & s[1]
        r, s = mickey_clock_kg(r, s, false, false)
    end
    
    z, r, s
end


#assert_k = BitArray(80)
#assert_iv = BitArray(80)

#r, s = mickey_init( assert_k, assert_iv )
#z, r, s = mickey_stream( 100, r, s )
#z

end
