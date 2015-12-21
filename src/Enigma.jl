
module Enigma

export enigma

    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    rotors = ["EKMFLGDQVZNTOWYHXUSPAIBRCJ" "AJDKSIRUXBLHWTMCQGZNPYFVOE" "BDFHJLCPRTXVZNYEIWGAKMUSQO" ]
    reflector = "YRUHQSLDPXNGOKMIEBFZCWVJAT"

    beg = 1

    function mod26(a)
        return ((a%26 + 26 )% 26)
    end

    function li(l)
        a = convert(Int8, l)
        b = convert(Int8, 'A')
        if(typeof(l) == Char)
            return (a - b)
        else
            return l
        end
    end


    function crypt(key, str)
        L = li(key[1])
        M = li(key[2])
        R = li(key[3])

        output = Array(UInt8, 0)
        for i in 1:length(str)
            if(str[i] == ' ')
                push!(output, ' ')
                continue
            end
            R = mod26(R + 1)
            if(R == 0)
                M = mod26(M + 1)
            end

            if(M == 0)
                L = mod26(L + 1)
            end

            a = rotors[3][beg + mod26(R + li(str[i]) )]

            b = rotors[2][beg + mod26(M + li(a) - R)]

            c = rotors[1][beg + mod26(L + li(b) - M)]
            d = reflector[beg + mod26(li(c) - L)]


            e = mod26(search(rotors[1], alphabet[beg + mod26(li(d) + L)]) - L ) - beg

            f = mod26(search(rotors[2], alphabet[beg + mod26(e + M)]) - M ) - beg
            index = mod26(search(rotors[3], alphabet[beg + mod26(f + R)])  - R  ) 
            if(index == 0)
                index = 26
            end
            ret = alphabet[index]
            push!(output, ret)
        end
        result = ""
        for i in output
            result = string(result, convert(Char, i))
        end
        return result
    end


    function swap(letters, msg)
        tmp = ""
        if(length(letters) == 0)
            return msg
        end
        for lett in split(letters)
            tmp = ""        
            for i in 1:length(msg)
                if(msg[i] == lett[1])
                    tmp = string(tmp, lett[2])
                elseif(msg[i] == lett[2])
                    tmp = string(tmp, lett[1])
                else
                    tmp = string(tmp, msg[i])
                end
            end
            msg = tmp
        end
        return tmp
    end


    function enigma(letters, key, msg)
		letters = uppercase(letters)
		key = uppercase(key)
		msg = uppercase(msg)
		if(length(key) < 3)
			key = "ABC"
		end
        swapedplainmsg = swap(letters, msg)
        encryptedmsg = crypt(key, swapedplainmsg)
        swapedencrypted = swap(letters, encryptedmsg)
        return swapedencrypted
    end
end


