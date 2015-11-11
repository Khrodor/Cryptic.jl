
module SHA2

export SHA256, SHA224

macro SHA_BLOCKSIZE()
    return :(64)
end

macro SHA_DIGESTSIZE()
    return :(32)
end

type SHA256
    digest_size
    digestsize
    block_size
    
    _sha
    
    SHA256()=new(@SHA_DIGESTSIZE(),@SHA_DIGESTSIZE(),@SHA_BLOCKSIZE(),sha_init())
    SHA256(s)=begin
        init=sha_init()
        sha_update(init,s)
        new(@SHA_DIGESTSIZE(),@SHA_DIGESTSIZE(),@SHA_BLOCKSIZE(),init)
    end
    
    #function init(self, s=None)
    #    self._sha = sha_init()
    #    if s
    #        sha_update(self._sha, getbuf(s))
    #    end
    #end

    #function copy(self)
    #    new = sha256.__new__(sha256)
    #    new._sha = self._sha.copy()
    #    return new
    #end
end
    
function digest(self::SHA256)
    return sha_final(self._sha.copy())[self._sha["digestsize"]]
end
    
function update(self::SHA256, s)
    sha_update(self._sha, getbuf(s))
end
    
function hexdigest(self::SHA256)
    res=""
    for i in self.digest()
        res=string(res,hex(i))
    end
    return res
end

type SHA224
    digest_size
    digestsize
    
    _sha
    
    SHA224()=new(28,28,sha224_init())
    SHA224(s)=begin
        init=sha224_init()
        sha_update(init,s)
        new(28,28,init)
    end
end

#function copy(self::SHA224)
#    new = sha224.__new__(sha224)
#    new._sha = self._sha.copy()
#    return new
#end

function new_shaobject()
    return Dict(
        "digest" => zeros(UInt64,8),
        "count_lo" => 0,
        "count_hi" => 0,
        "data" => zeros(UInt64,@SHA_BLOCKSIZE()),
        "local" => 0,
        "digestsize" => 0
    )
end

function ROR(x, y)
    (((x & 0xffffffff) >> (y & 31)) | (x << (32 - (y & 31)))) & 0xffffffff
end

function Ch(x, y, z)
   (z $ (x & (y $ z))) 
end

function Maj(x, y, z)
    (((x | y) & z) | (x & y))
end

function S(x, n)
    ROR(x, n)
end

function R(x, n)
    (x & 0xffffffff) >> n
end

function Sigma0(x)
    (S(x, 2) $ S(x, 13) $ S(x, 22))
end

function Sigma1(x)
    (S(x, 6) $ S(x, 11) $ S(x, 25))
end

function Gamma0(x)
    (S(x, 7) $ S(x, 18) $ R(x, 3))
end

function Gamma1(x)
    (S(x, 17) $ S(x, 19) $ R(x, 10))
end
    
function sha_transform(sha_info)
    W = []
    
    d = sha_info["data"]
    for i in 0:15
        push!(W,(d[4*i+1]<<24) + (d[4*i+2]<<16) + (d[4*i+3]<<8) + d[4*i+4])
    end
    
    for i in 17:64
        push!(W, (Gamma1(W[i - 2]) + W[i - 7] + Gamma0(W[i - 15]) + W[i - 16]) & 0xffffffff )
    end
    
    ss = sha_info["digest"][:]
    
    function RND(a,b,c,d,e,f,g,h,i::Int64,ki)
        t0 = h + Sigma1(e) + Ch(e, f, g) + ki + W[i]
        t1 = Sigma0(a) + Maj(a, b, c)
        d += t0
        h  = t0 + t1
        return d & 0xffffffff, h & 0xffffffff
    end
    
    ss[4], ss[8] = RND(ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[8],1,0x428a2f98)
    ss[3], ss[7] = RND(ss[8],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],2,0x71374491)
    ss[2], ss[6] = RND(ss[7],ss[8],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],3,0xb5c0fbcf)
    ss[1], ss[5] = RND(ss[6],ss[7],ss[8],ss[1],ss[2],ss[3],ss[4],ss[5],4,0xe9b5dba5)
    ss[8], ss[4] = RND(ss[5],ss[6],ss[7],ss[8],ss[1],ss[2],ss[3],ss[4],5,0x3956c25b)
    ss[7], ss[3] = RND(ss[4],ss[5],ss[6],ss[7],ss[8],ss[1],ss[2],ss[3],6,0x59f111f1)
    ss[6], ss[2] = RND(ss[3],ss[4],ss[5],ss[6],ss[7],ss[8],ss[1],ss[2],7,0x923f82a4)
    ss[5], ss[1] = RND(ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[8],ss[1],8,0xab1c5ed5)
    ss[4], ss[8] = RND(ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[8],9,0xd807aa98)
    ss[3], ss[7] = RND(ss[8],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],10,0x12835b01)
    ss[2], ss[6] = RND(ss[7],ss[8],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],11,0x243185be)
    ss[1], ss[5] = RND(ss[6],ss[7],ss[8],ss[1],ss[2],ss[3],ss[4],ss[5],12,0x550c7dc3)
    ss[8], ss[4] = RND(ss[5],ss[6],ss[7],ss[8],ss[1],ss[2],ss[3],ss[4],13,0x72be5d74)
    ss[7], ss[3] = RND(ss[4],ss[5],ss[6],ss[7],ss[8],ss[1],ss[2],ss[3],14,0x80deb1fe)
    ss[6], ss[2] = RND(ss[3],ss[4],ss[5],ss[6],ss[7],ss[8],ss[1],ss[2],15,0x9bdc06a7)
    ss[5], ss[1] = RND(ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[8],ss[1],16,0xc19bf174)
    ss[4], ss[8] = RND(ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[8],17,0xe49b69c1)
    ss[3], ss[7] = RND(ss[8],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],18,0xefbe4786)
    ss[2], ss[6] = RND(ss[7],ss[8],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],19,0x0fc19dc6)
    ss[1], ss[5] = RND(ss[6],ss[7],ss[8],ss[1],ss[2],ss[3],ss[4],ss[5],20,0x240ca1cc)
    ss[8], ss[4] = RND(ss[5],ss[6],ss[7],ss[8],ss[1],ss[2],ss[3],ss[4],21,0x2de92c6f)
    ss[7], ss[3] = RND(ss[4],ss[5],ss[6],ss[7],ss[8],ss[1],ss[2],ss[3],22,0x4a7484aa)
    ss[6], ss[2] = RND(ss[3],ss[4],ss[5],ss[6],ss[7],ss[8],ss[1],ss[2],23,0x5cb0a9dc)
    ss[5], ss[1] = RND(ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[8],ss[1],24,0x76f988da)
    ss[4], ss[8] = RND(ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[8],25,0x983e5152)
    ss[3], ss[7] = RND(ss[8],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],26,0xa831c66d)
    ss[2], ss[6] = RND(ss[7],ss[8],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],27,0xb00327c8)
    ss[1], ss[5] = RND(ss[6],ss[7],ss[8],ss[1],ss[2],ss[3],ss[4],ss[5],28,0xbf597fc7)
    ss[8], ss[4] = RND(ss[5],ss[6],ss[7],ss[8],ss[1],ss[2],ss[3],ss[4],29,0xc6e00bf3)
    ss[7], ss[3] = RND(ss[4],ss[5],ss[6],ss[7],ss[8],ss[1],ss[2],ss[3],30,0xd5a79147)
    ss[6], ss[2] = RND(ss[3],ss[4],ss[5],ss[6],ss[7],ss[8],ss[1],ss[2],31,0x06ca6351)
    ss[5], ss[1] = RND(ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[8],ss[1],32,0x14292967)
    ss[4], ss[8] = RND(ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[8],33,0x27b70a85)
    ss[3], ss[7] = RND(ss[8],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],34,0x2e1b2138)
    ss[2], ss[6] = RND(ss[7],ss[8],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],35,0x4d2c6dfc)
    ss[1], ss[5] = RND(ss[6],ss[7],ss[8],ss[1],ss[2],ss[3],ss[4],ss[5],36,0x53380d13)
    ss[8], ss[4] = RND(ss[5],ss[6],ss[7],ss[8],ss[1],ss[2],ss[3],ss[4],37,0x650a7354)
    ss[7], ss[3] = RND(ss[4],ss[5],ss[6],ss[7],ss[8],ss[1],ss[2],ss[3],38,0x766a0abb)
    ss[6], ss[2] = RND(ss[3],ss[4],ss[5],ss[6],ss[7],ss[8],ss[1],ss[2],39,0x81c2c92e)
    ss[5], ss[1] = RND(ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[8],ss[1],40,0x92722c85)
    ss[4], ss[8] = RND(ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[8],41,0xa2bfe8a1)
    ss[3], ss[7] = RND(ss[8],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],42,0xa81a664b)
    ss[2], ss[6] = RND(ss[7],ss[8],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],43,0xc24b8b70)
    ss[1], ss[5] = RND(ss[6],ss[7],ss[8],ss[1],ss[2],ss[3],ss[4],ss[5],44,0xc76c51a3)
    ss[8], ss[4] = RND(ss[5],ss[6],ss[7],ss[8],ss[1],ss[2],ss[3],ss[4],45,0xd192e819)
    ss[7], ss[3] = RND(ss[4],ss[5],ss[6],ss[7],ss[8],ss[1],ss[2],ss[3],46,0xd6990624)
    ss[6], ss[2] = RND(ss[3],ss[4],ss[5],ss[6],ss[7],ss[8],ss[1],ss[2],47,0xf40e3585)
    ss[5], ss[1] = RND(ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[8],ss[1],48,0x106aa070)
    ss[4], ss[8] = RND(ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[8],49,0x19a4c116)
    ss[3], ss[7] = RND(ss[8],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],50,0x1e376c08)
    ss[2], ss[6] = RND(ss[7],ss[8],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],51,0x2748774c)
    ss[1], ss[5] = RND(ss[6],ss[7],ss[8],ss[1],ss[2],ss[3],ss[4],ss[5],52,0x34b0bcb5)
    ss[8], ss[4] = RND(ss[5],ss[6],ss[7],ss[8],ss[1],ss[2],ss[3],ss[4],53,0x391c0cb3)
    ss[7], ss[3] = RND(ss[4],ss[5],ss[6],ss[7],ss[8],ss[1],ss[2],ss[3],54,0x4ed8aa4a)
    ss[6], ss[2] = RND(ss[3],ss[4],ss[5],ss[6],ss[7],ss[8],ss[1],ss[2],55,0x5b9cca4f)
    ss[5], ss[1] = RND(ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[8],ss[1],56,0x682e6ff3)
    ss[4], ss[8] = RND(ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[8],57,0x748f82ee)
    ss[3], ss[7] = RND(ss[8],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],58,0x78a5636f)
    ss[2], ss[6] = RND(ss[7],ss[8],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],59,0x84c87814)
    ss[1], ss[5] = RND(ss[6],ss[7],ss[8],ss[1],ss[2],ss[3],ss[4],ss[5],60,0x8cc70208)
    ss[8], ss[4] = RND(ss[5],ss[6],ss[7],ss[8],ss[1],ss[2],ss[3],ss[4],61,0x90befffa)
    ss[7], ss[3] = RND(ss[4],ss[5],ss[6],ss[7],ss[8],ss[1],ss[2],ss[3],62,0xa4506ceb)
    ss[6], ss[2] = RND(ss[3],ss[4],ss[5],ss[6],ss[7],ss[8],ss[1],ss[2],63,0xbef9a3f7)
    ss[5], ss[1] = RND(ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[8],ss[1],64,0xc67178f2)
    
    dig = []
    for i in collect(enumerate(sha_info["digest"]))
        push!(dig, (i[2] + ss[i[1]]) & 0xffffffff )
    end
    sha_info["digest"] = dig
end

function sha_init()
    sha_info = new_shaobject()
    sha_info["digest"] = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]
    sha_info["count_lo"] = 0
    sha_info["count_hi"] = 0
    sha_info["local"] = 0
    sha_info["digestsize"] = 32
    return sha_info
end

function sha224_init()
    sha_info = new_shaobject()
    sha_info["digest"] = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4]
    sha_info["count_lo"] = 0
    sha_info["count_hi"] = 0
    sha_info["local"] = 0
    sha_info["digestsize"] = 28
    return sha_info
end

function getbuf(s)
    if typeof(s) <: ASCIIString
        return s
    elseif typeof(s) <: Char
        return string(s)
    end
end


function sha_update(sha_info, buffer)
    count = length(buffer)
    buffer_idx = 0
    clo = (sha_info["count_lo"] + (count << 3)) & 0xffffffff
    if clo < sha_info["count_lo"]
        sha_info["count_hi"] += 1
    end
    sha_info["count_lo"] = clo
    
    sha_info["count_hi"] += (count >> 29)
    
    if sha_info["local"] > 0
        i = @SHA_BLOCKSIZE() - sha_info["local"]
        if i > count
            i = count
        end
        
        # copy buffer
        for x in enumerate(buffer[buffer_idx:buffer_idx+i])
            #sha_info["data"][sha_info["local"]+x[0]] = struct.unpack('B', x[1])[0]
        end
        
        count -= i
        buffer_idx += i
        
        sha_info["local"] += i
        if sha_info["local"] == @SHA_BLOCKSIZE()
            sha_transform(sha_info)
            sha_info["local"] = 0
        else
            return
        end
    end
    
    while count >= @SHA_BLOCKSIZE()
        # copy buffer
        #sha_info["data"] = [struct.unpack('B',c)[0] for c in buffer[buffer_idx:buffer_idx + @SHA_BLOCKSIZE]]
        count -= @SHA_BLOCKSIZE()
        buffer_idx += @SHA_BLOCKSIZE()
        sha_transform(sha_info)
    end
        
    
    # copy buffer
    pos = sha_info["local"]
    #sha_info["data"][pos:pos+count] = [struct.unpack('B',c)[0] for c in buffer[buffer_idx:buffer_idx + count]]
    sha_info["local"] = count
end

function sha_final(sha_info)
    lo_bit_count = sha_info["count_lo"]
    hi_bit_count = sha_info["count_hi"]
    count = (lo_bit_count >> 3) & 0x3f
    sha_info["data"][count] = 0x80
    count += 1
    if count > @SHA_BLOCKSIZE() - 8
        # zero the bytes in data after the count
        sha_info["data"] = length(sha_info["data"]) + (zeros(@SHA_BLOCKSIZE() - count))
        sha_transform(sha_info)
        # zero bytes in data
        sha_info["data"] = zeros(@SHA_BLOCKSIZE())
    else
        sha_info["data"] = length(sha_info["data"]) + (zeros(@SHA_BLOCKSIZE() - count))
    end
    
    sha_info["data"][56] = (hi_bit_count >> 24) & 0xff
    sha_info["data"][57] = (hi_bit_count >> 16) & 0xff
    sha_info["data"][58] = (hi_bit_count >>  8) & 0xff
    sha_info["data"][59] = (hi_bit_count >>  0) & 0xff
    sha_info["data"][60] = (lo_bit_count >> 24) & 0xff
    sha_info["data"][61] = (lo_bit_count >> 16) & 0xff
    sha_info["data"][62] = (lo_bit_count >>  8) & 0xff
    sha_info["data"][63] = (lo_bit_count >>  0) & 0xff
    
    sha_transform(sha_info)
    
    dig = []
    for i in sha_info["digest"]
        dig.extend([ ((i>>24) & 0xff), ((i>>16) & 0xff), ((i>>8) & 0xff), (i & 0xff) ])
    end
    result=""
    for i in dig
        result=string(result,Char(i))
    end
    return result
end


function test()
    a_str = "just a test string"
    
    assert("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" == sha256().hexdigest())
    assert("d7b553c6f09ac85d142415f857c5310f3bbbe7cdd787cce4b985acedd585266f" == sha256(a_str).hexdigest())
    assert("8113ebf33c97daa9998762aacafe750c7cefc2b2f173c90c59663a57fe626f21" == sha256(a_str*7).hexdigest())
    
    s = sha256(a_str)
    #s.update(a_str)
    assert("03d9963e05a094593190b6fc794cb1a3e1ac7d7883f0b5855268afeccc70d461" == s.hexdigest())
end

end
