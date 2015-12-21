module PrimeTests

export millerRabin

function millerRabin( n::BigInt, k::UInt = UInt(5) )
    # true if strong prime, false if composite
    
    assert( n > 3 )
    
    d = n - 1
    r = 0
    
    while d % 2 == 0
        r += 1 
        d = div(d, 2)
    end    
    
    for i in 1:k
        nextLoop = false
        
        a = rand( 2:(n-2) ) 
        
        x = powermod(a, d, n)
        
        if x == 1 || x == n - 1
            continue
        end
        
        for j in 1:(r-1)
            x = powermod(x, 2, n)
        
            if x == 1
                return false
            end
            
            if x == n - 1
                nextLoop = true
                break
            end
               
        end
        
        if nextLoop
            continue
        end
        
        return false
        
    end
    
    return true
    
end

function millerRabinDeterministic( n::BigInt )
    
    assert( n > 1 )
    
    d = n - 1
    s = 0
    
    while d % 2 == 0
        s += 1 
        d = div(d, 2)
    end    

    loopMin = BigInt( min( n - 1, floor( 2 * (log(n)^2) ) ) )
    
    for a in 2:( loopMin )
        
        nextLoop = false
        flag = false
        
        for r in 0:(s-1)
            
            if powermod(a, d, n) == 1 || powermod(a, 2^r * d  , n) == n - 1
                nextLoop = true
                break
            end
            
        end
        
        if nextLoop
            continue
        end
        
        return false
    
    end
    
    return true
    
end





function composites( n )
   
    prim = primes( n )
    primCnt = 1
    comps = Array{BigInt}(0)
    
    for i in 2:n
        
        if prim[ primCnt ] == i
            primCnt += 1
            
            if primCnt > length( prim )
                primCnt = length( prim )
            end
        else
            push!( comps, i )
        end

    end
    
    comps
end

function compareMillerRabinProbAndDet( iterMax )

    for iter in 1:iterMax

        n = rand( 3:1000000000000000000000000000000000000000000000000000000000000000000000000000 )

        prob = millerRabin( n, UInt(1) )
        deter = millerRabinDeterministic( n )

        if deter == false && prob == true
            warn( "Probabilistic algorithm says prime, deterministic says composite  "  )
            warn( n )
            return false
        end

        if deter == true && prob == false
            #try to find 
            iters = [10 50 100]

            warn( "Couldn't determine that n is prime for ", 5, " iterations" )
            warn( n )

            for i in iters
                if millerRabin( n, i ) == true
                    continue
                end
                
                warn( "Couldn't determine that n is prime for ", maximum(iters), " iterations" )
                warn( n )

            end

        end

    end
    
    return true
    
end

function selftest()

    assert( all([ millerRabin( BigInt(x) ) for x in primes( 100000 )[3:end] ]) )
    assert( all([ millerRabinDeterministic( BigInt(x) ) for x in primes( 1000 )[1:end] ]) )
    assert( compareMillerRabinProbAndDet( 100 ) )
    
    compareMillerRabinProbAndDet( 1000 )
    any([ millerRabinDeterministic( BigInt(x) ) for x in 10:2:10000  ])
    
    assert( length(intersect( composites(100000), primes(100000) )) == 0 )
    
end



end
 
