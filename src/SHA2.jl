
module SHA2

export SHA256, compute

macro SHA256BLOCKSIZE()
    const block::UInt32 = (512/8)
    return :($block)
end
macro DIGESTSIZE()
    const size::UInt32 = (256/8)
    return :($size)
end

macro SHA256K(idx)
    const sha256k::Array{Int64} = 
        [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]
    return :($sha256k[$idx])
end

type SHA256
    mtotlen::UInt32
    mlen::UInt32
    mblock::Array{UInt8}
    mh::Array{UInt32}

    message::Array{UInt8}
    
    SHA256(message::ASCIIString)=begin
        local mh::Array{UInt32}=zeros(UInt8,8)
        mh[1] = 0x6a09e667
        mh[2] = 0xbb67ae85
        mh[3] = 0x3c6ef372
        mh[4] = 0xa54ff53a
        mh[5] = 0x510e527f
        mh[6] = 0x9b05688c
        mh[7] = 0x1f83d9ab
        mh[8] = 0x5be0cd19
        
        local buffer::Array{UInt8}
        if isfile(message)
            file::IOStream = open(message)
            content::ASCIIString=readall(file)
            close(file)
            buffer=Vector{UInt8}(content)
        else
            buffer=Vector{UInt8}(message)
        end
        new(0, 0, zeros(UInt8, 128), mh, buffer)
    end
end

SHA2_SHFR(x, n) = (x >> n)
SHA2_ROTR(x, n) = ((x >> n) | (x << ((sizeof(x) << 3) - n)))
SHA2_ROTL(x, n) = ((x << n) | (x >> ((sizeof(x) << 3) - n)))
SHA2_CH(x, y, z) = ((x & y) $ (~x & z))
SHA2_MAJ(x, y, z) = ((x & y) $ (x & z) $ (y & z))
SHA256_F1(x) = (SHA2_ROTR(x,  2) $ SHA2_ROTR(x, 13) $ SHA2_ROTR(x, 22))
SHA256_F2(x) = (SHA2_ROTR(x,  6) $ SHA2_ROTR(x, 11) $ SHA2_ROTR(x, 25))
SHA256_F3(x) = (SHA2_ROTR(x,  7) $ SHA2_ROTR(x, 18) $ SHA2_SHFR(x,  3))
SHA256_F4(x) = (SHA2_ROTR(x, 17) $ SHA2_ROTR(x, 19) $ SHA2_SHFR(x, 10))

function SHA2_PACK32(str::AbstractArray{UInt8}, x::AbstractArray{UInt32})
    local val::UInt32 = 0
    try
        val |= (str[4])
    end
    try
        val |= (UInt32(str[3]) << 8)
    end
    try
        val |= (UInt32(str[2]) << 16)
    end
    val |= (UInt32(str[1]) << 24)
    x[1]=val
end

function SHA2_UNPACK32(x::AbstractArray{UInt32}, str::AbstractArray{UInt8})
    try
        str[4] |= UInt8(x[1] & 0xff)
    end
    try
        str[3] |= UInt8((x[1] >> 8) & 0xff)
    end
    try
        str[2] |= UInt8((x[1] >> 16) & 0xff)
    end
    str[1] |= UInt8(x[1] >> 24)
end

function transform(message::Array{UInt8}, block_nb::UInt32, mh::Array{UInt32})
    w::Array{UInt32}=zeros(UInt32, 64)
    wv::Array{UInt32}=zeros(UInt32, 8)
    t1::UInt32=0
    t2::UInt32=0
    sub_block::Array{UInt8}=zeros(UInt8)
    i::Int32=0
    j::Int32=0
    for i in 1:1:block_nb
        sub_block = message[((i-1)<< 6)+1:end]
        for j in 1:1:16
            try
                SHA2_PACK32(sub(sub_block, ((j-1)<<2)+1:((j-1)<<2)+1), sub(w, j:j))
            end
        end
        for j in 17:1:64
            w[j] =  SHA256_F4(w[j -  2]) + w[j -  7] + SHA256_F3(w[j - 15]) + w[j - 16]
        end
        for j in 1:1:8
            wv[j] = mh[j]
        end
        for j in 1:1:64
            t1 = UInt64(wv[8] + SHA256_F2(wv[5]) + SHA2_CH(wv[5], wv[6], wv[7]) + @SHA256K(j) + w[j])%(typemax(UInt32)+1)
            t2 = SHA256_F1(wv[1]) + SHA2_MAJ(wv[1], wv[2], wv[3])
            wv[8] = wv[7]
            wv[7] = wv[6]
            wv[6] = wv[5]
            wv[5] = wv[4] + t1
            wv[4] = wv[3]
            wv[3] = wv[2]
            wv[2] = wv[1]
            wv[1] = t1 + t2
        end
        for j in 1:1:8
            mh[j] += wv[j]
        end
    end
end

function final(ctx::SHA256, digest::Array{UInt8})
    block_nb::UInt32=0
    m_block::Array{UInt8}=ctx.mblock
    pm_len::UInt32=0
    len_b::UInt32=0
    i::Int32=0
    block_nb = (1 + ((@SHA256BLOCKSIZE() - 9) < (m_len % @SHA256BLOCKSIZE())))
    len_b = (m_tot_len + m_len) << 3
    pm_len = block_nb << 6
    memset(m_block + m_len, 0, pm_len - m_len)
    m_block[m_len] = 0x80
    SHA2_UNPACK32(len_b, m_block + pm_len - 4)
    transform(m_block, block_nb)
    for i in 1:1:8
        SHA2_UNPACK32(m_h[i], &digest[i << 2])
    end
end

function update(ctx::SHA256)
    message::Array{UInt8}=ctx.message
    len::UInt32=length(message)
    block_nb::UInt32=0
    new_len::UInt32=rem_len::UInt32=tmp_len::UInt32=0
    shifted_message::Array{UInt8}=zeros(0)
    tmp_len = @SHA256BLOCKSIZE() - ctx.mlen
    rem_len = len < tmp_len ? len : tmp_len
    if (ctx.mlen + len < @SHA256BLOCKSIZE())
        ctx.mlen += len
        return
    end
    new_len = len - rem_len
    block_nb = div(new_len, @SHA256BLOCKSIZE())
    shifted_message = ctx.message[rem_len+1:end]
    transform(message, UInt32(1), ctx.mh)
    transform(shifted_message, block_nb, ctx.mh)
    rem_len = new_len % @SHA256BLOCKSIZE()
    ctx.mblock = shifted_message
    ctx.mlen = rem_len
    ctx.mtotlen += (block_nb + 1) << 6
end

function compute(ctx::SHA256)
    local digest::Array{UInt8}=zeros(UInt8, @DIGESTSIZE())
    
    #ctx.update( (unsigned char*)input.c_str(), input.length());
    final(ctx, digest);
 
    local buf::Array{UInt8}=zeros(UInt8, 2*@DIGESTSIZE()+1)
    buf[2*@DIGESTSIZE()] = 0
    for i in 1:1:@DIGESTSIZE()
        sprintf(buf+i*2, "%02x", digest[i])
    end
    return convert(ASCIIString, buf)
end

#tests
function tests()
    fraze::ASCIIString="some testing sha256 string"
    #type
    sha256Obj::SHA256 = SHA256(fraze)
    sha256InitArray::Array{UInt32}=[1779033703, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635, 1541459225]
    assert(length(setdiff(sha256Obj.mh, sha256InitArray)) == 0)
    #------------
    
    #pack
    assert(SHA2_PACK32(sub(Vector{UInt8}(fraze),1:1), [UInt32(3435973836)]) == 1936682341)
    #-----------
    
    #unpack
    initialZerosUnpack::Array{UInt8}=zeros(UInt8,4)
    SHA2_UNPACK32([UInt32(2150498334)], sub(initialZerosUnpack,1:1))
    assert(initialZerosUnpack == [128, 46, 0, 30])
    #-----------
    
    assert(@SHA256K(4) == 3921009573)
    assert(@SHA256K(34) == 773529912)
    
    #transform
    shaInitArray::Array{UInt32}=[1779033703, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635, 1541459225]
    shaTransformResultArray::Array{UInt32}=[2150498334, 574004025, 4117243134, 3137152410, 3814864597, 1316592077, 4145884613, 322703246]
    transformTestFraze::Array{UInt8}=zeros(UInt8,64)
    transformTestFraze[1:21]=Vector{UInt8}("some test for sha2561")
    transformTestFraze[21]=128
    transformTestFraze[64]=160
    transform(transformTestFraze, UInt32(1), shaInitArray)
    assert(length(setdiff(shaInitArray, shaTransformResultArray)) == 0)
    #------------
    
    #update
    updateTestObject::SHA256=SHA256("some test for sha256some test for sha256some test for sha256some test for sha256")
    update(updateTestObject)
    assert(updateTestObject.mtotlen == 64)
    assert(updateTestObject.mlen == 16)
    assert(length(setdiff(updateTestObject.mblock, Vector{UInt8}(" test for sha256a256some test for sha256some test for sha256some"))) == 0)
    assert(length(setdiff(updateTestObject.mh, [3687268025, 3275113092, 2361836355, 1273340655, 2721684165, 1592557147, 902732290, 2085669382])) == 0)
    #------------
    
    #compute
    
    #------------
    
    #final
    
    #------------
end
tests()

end

workspace()
