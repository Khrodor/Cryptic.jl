
module SHA2

export SHA256, compute!

macro sha256blocksize()
    const block::UInt32 = (512/8)
    return :($block)
end
macro digestsize()
    const size::UInt32 = (256/8)
    return :($size)
end

macro sha256k(idx)
    const sha256karr::Array{Int64} = 
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
    return :($sha256karr[$idx])
end

type SHA256
    mtotlen::UInt32
    mlen::UInt32
    mblock::AbstractArray{UInt8}
    mh::Array{UInt32}

    message::Array{UInt8}
    
    SHA256(message::ASCIIString; file::Bool=false)=begin
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
        if file && isfile(message)
            f::IOStream = open(message)
            content::ASCIIString=readall(f)
            close(f)
            buffer=Vector{UInt8}(content)
        else
            buffer=Vector{UInt8}(message)
        end
        new(0, 0, zeros(UInt8, 128), mh, buffer)
    end
end

sha2shfr(x, n) = (x >> n)
sha2rotr(x, n) = ((x >> n) | (x << ((sizeof(x) << 3) - n)))
sha2rotl(x, n) = ((x << n) | (x >> ((sizeof(x) << 3) - n)))
sha2ch(x, y, z) = ((x & y) $ (~x & z))
sha2maj(x, y, z) = ((x & y) $ (x & z) $ (y & z))
sha256f1(x) = (sha2rotr(x,  2) $ sha2rotr(x, 13) $ sha2rotr(x, 22))
sha256f2(x) = (sha2rotr(x,  6) $ sha2rotr(x, 11) $ sha2rotr(x, 25))
sha256f3(x) = (sha2rotr(x,  7) $ sha2rotr(x, 18) $ sha2shfr(x,  3))
sha256f4(x) = (sha2rotr(x, 17) $ sha2rotr(x, 19) $ sha2shfr(x, 10))

function sha2pack32!(str::AbstractArray{UInt8}, x::AbstractArray{UInt32})
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

function sha2unpack32!(x::UInt32, str::AbstractArray{UInt8})
    try
        str[4] |= UInt8(x & 0xff)
    end
    try
        str[3] |= UInt8((x >> 8) & 0xff)
    end
    try
        str[2] |= UInt8((x >> 16) & 0xff)
    end
    str[1] |= UInt8(x >> 24)
end

function transform!(message::Array{UInt8}, blocknb::UInt32, mh::Array{UInt32})
    local w::Array{UInt32}=zeros(UInt32, 64)
    local wv::Array{UInt32}=zeros(UInt32, 8)
    local t1::UInt32=0
    local t2::UInt32=0
    local subblock::AbstractArray{UInt8}=zeros(UInt8)
    local i::Int32=0
    local j::Int32=0
    for i in 1:1:blocknb
        subblock = sub(message, ((i-1)<< 6)+1:length(message))
        for j in 1:1:16
            try
                sha2pack32!(sub(subblock, ((j-1)<<2)+1:((j-1)<<2)+1), sub(w, j:j))
            end
        end
        for j in 17:1:64
            w[j] =  sha256f4(w[j -  2]) + w[j -  7] + sha256f3(w[j - 15]) + w[j - 16]
        end
        for j in 1:1:8
            wv[j] = mh[j]
        end
        for j in 1:1:64
            t1 = UInt64(wv[8] + sha256f2(wv[5]) + sha2ch(wv[5], wv[6], wv[7]) + @sha256k(j) + w[j])%(typemax(UInt32)+1)
            t2 = sha256f1(wv[1]) + sha2maj(wv[1], wv[2], wv[3])
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

function update!(ctx::SHA256)
    message::Array{UInt8}=ctx.message
    local len::UInt32=length(message)
    local blocknb::UInt32=0
    local newlen::UInt32=remlen::UInt32=tmplen::UInt32=0
    local shiftedmessage::Array{UInt8}=zeros(0)
    local tmplen = @sha256blocksize() - ctx.mlen
    local remlen = len < tmplen ? len : tmplen
    ctx.mblock[1:remlen]=message[1:remlen]
    if (ctx.mlen + len < @sha256blocksize())
        ctx.mlen += len
        return
    end
    newlen = len - remlen
    blocknb = div(newlen, @sha256blocksize())
    shiftedmessage = ctx.message[remlen+1:end]
    transform!(message, UInt32(1), ctx.mh)
    transform!(shiftedmessage, blocknb, ctx.mh)
    remlen = newlen % @sha256blocksize()
    
    local maxidx = length(shiftedmessage) > 128 ? 128 : length(shiftedmessage)
    
    ctx.mblock[1:maxidx] = shiftedmessage[1:maxidx]
    ctx.mlen = remlen
    ctx.mtotlen += (blocknb + 1) << 6
end

function final!(ctx::SHA256, digest::Array{UInt8})
    local blocknb::UInt32=0
    local pmlen::UInt32=0
    local lenb::UInt32=0
    local i::Int32=0
    blocknb = (1 + ((@sha256blocksize() - 9) < (ctx.mlen % @sha256blocksize())))
    lenb = (ctx.mtotlen + ctx.mlen) << 3
    pmlen = blocknb << 6
    ctx.mblock[ctx.mlen+1:end]=zeros(UInt8, length(ctx.mblock)-ctx.mlen)
    
    ctx.mblock[ctx.mlen+1] = 0x80
    sha2unpack32!(lenb, sub(ctx.mblock, pmlen-3:pmlen-3))
    transform!(ctx.mblock, blocknb, ctx.mh)
    for i in 1:1:8
        sha2unpack32!(ctx.mh[i], sub(digest, ((i-1) << 2)+1:((i-1) << 2)+1))
    end
end

function compute!(ctx::SHA256)
    local digest::Array{UInt8}=zeros(UInt8, @digestsize())
    
    update!(ctx)
    final!(ctx, digest)
 
    local buf::Array{UInt8}=zeros(UInt8, 2*@digestsize()+1)
    buf[2*@digestsize()] = 0
    buf=bytes2hex(digest)
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
    assert(sha2pack32!(sub(Vector{UInt8}(fraze),1:1), [UInt32(3435973836)]) == 1936682341)
    #-----------
    
    #unpack
    initialZerosUnpack::Array{UInt8}=zeros(UInt8,4)
    sha2unpack32!(UInt32(2150498334), sub(initialZerosUnpack,1:1))
    assert(initialZerosUnpack == [128, 46, 0, 30])
    #-----------
    
    assert(@sha256k(4) == 3921009573)
    assert(@sha256k(34) == 773529912)
    
    #transform
    shaInitArray::Array{UInt32}=[1779033703, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635, 1541459225]
    shaTransformResultArray::Array{UInt32}=[2150498334, 574004025, 4117243134, 3137152410, 3814864597, 1316592077, 4145884613, 322703246]
    transformTestFraze::Array{UInt8}=zeros(UInt8,64)
    transformTestFraze[1:21]=Vector{UInt8}("some test for sha2561")
    transformTestFraze[21]=128
    transformTestFraze[64]=160
    transform!(transformTestFraze, UInt32(1), shaInitArray)
    assert(length(setdiff(shaInitArray, shaTransformResultArray)) == 0)
    #------------
    
    #update
    updateTestObject::SHA256=SHA256("some test for sha256some test for sha256some test for sha256some test for sha256")
    update!(updateTestObject)
    assert(updateTestObject.mtotlen == 64)
    assert(updateTestObject.mlen == 16)
    updateFrazeResult::Array{UInt8}=zeros(UInt8,128)
    updateFrazeResult[1:64]=Vector{UInt8}(" test for sha256a256some test for sha256some test for sha256some")
    assert(length(setdiff(updateTestObject.mblock, updateFrazeResult)) == 0)
    assert(length(setdiff(updateTestObject.mh, [3687268025, 3275113092, 2361836355, 1273340655, 2721684165, 1592557147, 902732290, 2085669382])) == 0)
    #------------
    
    #compute
    computeTestObject::SHA256=SHA256("some test for sha256some test for sha256some test for sha256some test for sha256")
    assert(compute!(computeTestObject) == "7b03aec00cab2d25c4f9786dde478622197aec26912aa224e4cb04ee14072fc9")
    #------------
    
    overallTest1::SHA256=SHA256("Test")
    res1::ASCIIString=compute!(overallTest1)
    overallTest2::SHA256=SHA256(res1)
    res2::ASCIIString=compute!(overallTest2)
    overallTest3::SHA256=SHA256(res2)
    res3::ASCIIString=compute!(overallTest3)
    assert(res1 == "532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25")
    assert(res2 == "28cac1a9a8d521b6aa3b454a19d592e5a113d08a2fbcfefb8a7b977fea140cdd")
    assert(res3 == "3c00539acd235bde9eb4117f1fa04a6c274ee282a54cdbce88a3854022ebcc79")
end
tests()

end

