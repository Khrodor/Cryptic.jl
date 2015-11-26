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

end
 
