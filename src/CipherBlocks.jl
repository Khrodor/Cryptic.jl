
module CipherBlocks
export ECB, CBC, CFB, encrypt, decrypt

type ECB 
    blocksize::Int
    data::Array{UInt8}
    key::Array{UInt8}
    encryptFunction::Function
    decryptFunction::Function
    ECB(blocksize, data, key, encryptFunction, decryptFunction) = 
    new(blocksize/8, data, key, encryptFunction, decryptFunction)
end

type CBC
    blocksize::Int
    data::Array{UInt8}
    key::Array{UInt8}
    encryptFunction::Function
    decryptFunction::Function
    initialVector::Array{UInt8}
    CBC(blocksize, data, key, encryptFunction, decryptFunction, initialVector) = new(blocksize/8, data, key, encryptFunction, decryptFunction, initialVector)
end

type CFB
    blocksize::Int
    data::Array{UInt8}
    key::Array{UInt8}
    encryptFunction::Function
    decryptFunction::Function
    initialVector::Array{UInt8}
    CFB(blocksize, data, key, encryptFunction, decryptFunction, initialVector) = new(blocksize/8, data, key, encryptFunction, decryptFunction, initialVector)
end

function encrypt(blocktype::CipherBlocks.ECB)
    blockCount = ceil(length(blocktype.data) / blocktype.blocksize)
    encryptedData = Array{UInt8}(0)
    for cnt in 1:blockCount
        if(cnt * blocktype.blocksize < length(blocktype.data))
            dataBlock = blocktype.data[(cnt * blocktype.blocksize) - blocktype.blocksize + 1 : cnt * blocktype.blocksize]
            append!(encryptedData, blocktype.encryptFunction(dataBlock, blocktype.key))
        else
            dataBlock = blocktype.data[(cnt * blocktype.blocksize) - blocktype.blocksize + 1 : end]
            append!(dataBlock, [1;zeros(UInt8, (blocktype.blocksize-length(dataBlock)-1))])
            append!(encryptedData, blocktype.encryptFunction(dataBlock, blocktype.key))
        end
    end
    return encryptedData
end

function decrypt(blocktype::CipherBlocks.ECB)
    blockCount = ceil(length(blocktype.data) / blocktype.blocksize)
    decryptedData = Array{UInt8}(0)
    for cnt in 1:blockCount
        if(cnt * blocktype.blocksize < length(blocktype.data))
            dataBlock = blocktype.data[(cnt * blocktype.blocksize) - blocktype.blocksize + 1 : cnt * blocktype.blocksize]
        else
            dataBlock = blocktype.data[(cnt * blocktype.blocksize) - blocktype.blocksize + 1 : end]
        end
        append!(decryptedData, blocktype.encryptFunction(dataBlock, blocktype.key))
    end
    if(length(decryptedData) < blockCount*blocktype.blocksize)
        append!(decryptedData, zeros(UInt8, convert(Int,((blockCount*blocktype.blocksize)-length(decryptedData)))))
    end
    return decryptedData
end

function encrypt(blocktype::CipherBlocks.CBC)
    blockCount = ceil(length(blocktype.data) / blocktype.blocksize)
    encryptedData = Array{UInt8}(0)
    dataBlock = blocktype.data[1 : blocktype.blocksize]
    dataBlock = dataBlock $ blocktype.initialVector
    append!(encryptedData, blocktype.encryptFunction(dataBlock, blocktype.key))
    for cnt in 2:blockCount
        if(cnt * blocktype.blocksize < length(blocktype.data))
            dataBlock = blocktype.data[(cnt * blocktype.blocksize) - blocktype.blocksize + 1 : cnt * blocktype.blocksize]
            dataBlock = dataBlock $ encryptedData[cnt-1]
        else            
            dataBlock = blocktype.data[(cnt * blocktype.blocksize) - blocktype.blocksize + 1 : end]
            dataBlock = dataBlock $ encryptedData[cnt-1]
        end
        append!(encryptedData, blocktype.encryptFunction(dataBlock, blocktype.key))
    end
    if(length(encryptedData) < blockCount*blocktype.blocksize)
        append!(encryptedData, zeros(UInt8, convert(Int,((blockCount*blocktype.blocksize)-length(encryptedData)))))
        encryptedData[length(blocktype.data)+1] = 1;
    end
    return encryptedData
end

function decrypt(blocktype::CipherBlocks.CBC)
    blockCount = ceil(length(blocktype.data) / blocktype.blocksize)
    decryptedData = Array{UInt8}(0)
    dataBlock = blocktype.data[1 : blocktype.blocksize]
    dataBlock = blocktype.encryptFunction(dataBlock, blocktype.key) $ blocktype.initialVector
    append!(decryptedData, dataBlock)
    for cnt in 2:blockCount
        if(cnt * blocktype.blocksize < length(blocktype.data))
            dataBlock = blocktype.data[(cnt * blocktype.blocksize) - blocktype.blocksize + 1 : cnt * blocktype.blocksize]
            xorvec = blocktype.data[((cnt-1) * blocktype.blocksize) - blocktype.blocksize + 1 : cnt * blocktype.blocksize]
            dataBlock = blocktype.decryptFunction(dataBlock, blocktype,key) $ xorvec
        else            
            dataBlock = blocktype.data[(cnt * blocktype.blocksize) - blocktype.blocksize + 1 : end]
            xorvec = blocktype.data[((cnt-1) * blocktype.blocksize) - blocktype.blocksize + 1 : cnt * blocktype.blocksize]
            dataBlock = blocktype.decryptFunction(dataBlock, blocktype,key) $ xorvec
        end
        append!(encryptedData, dataBlock)
    end
    if(length(decryptedData) < blockCount*blocktype.blocksize)
        append!(decryptedData, zeros(UInt8, convert(Int,((blockCount*blocktype.blocksize)-length(decryptedData)))))
        decryptedData[length(blocktype.data)+1] = 1;
    end
    return decryptedData
end

function encrypt(blocktype::CipherBlocks.CFB)
    blockCount = ceil(length(blocktype.data) / blocktype.blocksize)
    encryptedData = Array{UInt8}(0)
    dataBlock = blocktype.data[1 : blocktype.blocksize]
    xorvec = blocktype.encryptFunction(blocktype.initialVector)
    dataBlock = dataBlock $ xorvec
    append!(encryptedData, dataBlock)
    for cnt in 2:blockCount
        if(cnt * blocktype.blocksize < length(blocktype.data))
            xorvec = blocktype.encryptedFunction(dataBlock)
            dataBlock = blocktype.data[(cnt * blocktype.blocksize) - blocktype.blocksize + 1 : cnt * blocktype.blocksize]
            dataBlock = dataBlock $ xorvec
        else     
            xorvec = blocktype.encryptedFunction(dataBlock)       
            dataBlock = blocktype.data[(cnt * blocktype.blocksize) - blocktype.blocksize + 1 : end]
            dataBlock = dataBlock $ xorvec
        end
        append!(encryptedData, dataBlock)
    end
    if(length(encryptedData) < blockCount*blocktype.blocksize)
        append!(encryptedData, zeros(UInt8, convert(Int,((blockCount*blocktype.blocksize)-length(encryptedData)))))
        encryptedData[length(blocktype.data)+1] = 1;
    end
    return encryptedData
end

function decrypt(blocktype::CipherBlocks.CFB)
    blockCount = ceil(length(blocktype.data) / blocktype.blocksize)
    decryptedData = Array{UInt8}(0)
    dataBlock = blocktype.data[1 : blocktype.blocksize]
    xorvec = blocktype.decryptFunction(blocktype.initialVector)
    dataBlock = dataBlock $ xorvec
    append!(decryptedData, dataBlock)
    for cnt in 2:blockCount
        if(cnt * blocktype.blocksize < length(blocktype.data))
            xorvec = blocktype.data[((cnt-1) * blocktype.blocksize) - blocktype.blocksize + 1 : cnt * blocktype.blocksize]
            xorvec = blocktype.decryptFunction(xorvec)
            dataBlock = blocktype.data[(cnt * blocktype.blocksize) - blocktype.blocksize + 1 : cnt * blocktype.blocksize]
            dataBlock = dataBlock $ xorvec
        else        
            xorvec = blocktype.data[((cnt-1) * blocktype.blocksize) - blocktype.blocksize + 1 : cnt * blocktype.blocksize]
            xorvec = blocktype.decryptFunction(xorvec)
            dataBlock = blocktype.data[(cnt * blocktype.blocksize) - blocktype.blocksize + 1 : end]
            dataBlock = dataBlock $ xorvec
        end
        append!(encryptedData, dataBlock)
    end
    if(length(decryptedData) < blockCount * blocktype.blocksize)
        append!(decryptedData, zeros(UInt8, convert(Int,((blockCount*blocktype.blocksize)-length(decryptedData)))))
        decryptedData[length(blocktype.data)+1] = 1;
    end
    return decryptedData
end

end
