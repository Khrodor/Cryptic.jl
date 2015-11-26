
module CipherBlocks
export ECB, CBC, CFB, encrypt, decrypt

type ECB 
    blocksize::Int
    data::Array{UInt8}
    key::Array{UInt8}
    encryptFunction::Function
    decryptFunction::Function
    ECB(blocksize, data, key, encryptFunction, decryptFunction) = new(blocksize/8, data, key, encryptFunction, decryptFunction)
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
    blockCount = Int(ceil(length(blocktype.data) / blocktype.blocksize))
    encryptedData = Array{UInt8}(0)
    for cnt in 1:blockCount
        if(cnt * blocktype.blocksize < length(blocktype.data))
            dataBlock = blocktype.data[((cnt-1) * blocktype.blocksize) + 1 : cnt * blocktype.blocksize]
            append!(encryptedData, blocktype.encryptFunction(dataBlock, blocktype.key))
        else
            dataBlock = blocktype.data[((cnt-1) * blocktype.blocksize) + 1 : end]
            append!(dataBlock, [1;zeros(UInt8, (blocktype.blocksize-length(dataBlock)-1))])
            append!(encryptedData, blocktype.encryptFunction(dataBlock, blocktype.key))
        end
    end
    return encryptedData
end

function decrypt(blocktype::CipherBlocks.ECB, encryptedData::Array{UInt8})
    blockCount = Int(ceil(length(encryptedData) / blocktype.blocksize))
    decryptedData = Array{UInt8}(0)
    for cnt in 1:blockCount
        if(cnt * blocktype.blocksize < length(blocktype.data))
            dataBlock = encryptedData[((cnt-1) * blocktype.blocksize) + 1 : cnt * blocktype.blocksize]
        else
            dataBlock = encryptedData[((cnt-1) * blocktype.blocksize) + 1 : end]
        end
        append!(decryptedData, blocktype.encryptFunction(dataBlock, blocktype.key))
    end
    decryptedData = decryptedData[1:length(blocktype.data)]
    return decryptedData
end

function encrypt(blocktype::CipherBlocks.CBC)
    blockCount = Int(ceil(length(blocktype.data) / blocktype.blocksize))
    encryptedData = Array{UInt8}(0)
    dataBlock = blocktype.data[1 : blocktype.blocksize]
    dataBlock = dataBlock $ blocktype.initialVector
    encryptedBlock = blocktype.encryptFunction(dataBlock, blocktype.key)
    append!(encryptedData, encryptedBlock)
    for cnt in 2:blockCount
        if(cnt * blocktype.blocksize < length(blocktype.data))
            dataBlock = blocktype.data[((cnt-1) * blocktype.blocksize) + 1 : cnt * blocktype.blocksize]
            dataBlock $= encryptedBlock
        else            
            dataBlock = blocktype.data[((cnt-1) * blocktype.blocksize) + 1 : end]
            append!(dataBlock, [1;zeros(UInt8, (blocktype.blocksize-length(dataBlock)-1))])
            dataBlock $= encryptedBlock
        end
        encryptedBlock = blocktype.encryptFunction(dataBlock, blocktype.key)
        append!(encryptedData, encryptedBlock)
    end
    return encryptedData
end

function decrypt(blocktype::CipherBlocks.CBC, encryptedData::Array{UInt8})
    blockCount = Int(ceil(length(encryptedData) / blocktype.blocksize))
    decryptedData = Array{UInt8}(0)
    dataBlock = encryptedData[1 : blocktype.blocksize]
    dataBlock = blocktype.decryptFunction(dataBlock, blocktype.key) $ blocktype.initialVector
    append!(decryptedData, dataBlock)
    for cnt in 2:blockCount
        if(cnt * blocktype.blocksize < length(blocktype.data))
            dataBlock = encryptedData[((cnt-1) * blocktype.blocksize)+1 : cnt * blocktype.blocksize]
            xorvec = encryptedData[((cnt-2) * blocktype.blocksize)+1 : (cnt-1) * blocktype.blocksize]
            dataBlock = blocktype.decryptFunction(dataBlock, blocktype.key) $ xorvec
        else            
            dataBlock = encryptedData[((cnt-1) * blocktype.blocksize)+1 : end]
            xorvec = encryptedData[((cnt-2) * blocktype.blocksize)+1 : (cnt-1) * blocktype.blocksize]
            dataBlock = blocktype.decryptFunction(dataBlock, blocktype.key) $ xorvec
        end
        append!(decryptedData, dataBlock)
    end
    decryptedData = decryptedData[1:length(blocktype.data)]
    return decryptedData
end

function encrypt(blocktype::CipherBlocks.CFB)
    blockCount = Int(ceil(length(blocktype.data) / blocktype.blocksize))
    encryptedData = Array{UInt8}(0)
    dataBlock = blocktype.data[1 : blocktype.blocksize]
    xorvec = blocktype.encryptFunction(blocktype.initialVector, blocktype.key)
    dataBlock = dataBlock $ xorvec
    append!(encryptedData, dataBlock)
    for cnt in 2:blockCount
        if(cnt * blocktype.blocksize < length(blocktype.data))
            xorvec = blocktype.encryptFunction(dataBlock, blocktype.key)
            dataBlock = blocktype.data[((cnt-1) * blocktype.blocksize) + 1 : cnt * blocktype.blocksize]
            dataBlock = dataBlock $ xorvec
        else     
            xorvec = blocktype.encryptFunction(dataBlock, blocktype.key)       
            dataBlock = blocktype.data[((cnt-1) * blocktype.blocksize) + 1 : end]
            append!(dataBlock, [1;zeros(UInt8, (blocktype.blocksize-length(dataBlock)-1))])
            dataBlock = dataBlock $ xorvec
        end
        append!(encryptedData, dataBlock)
    end
    return encryptedData
end

function decrypt(blocktype::CipherBlocks.CFB, encryptedData::Array{UInt8})
    blockCount = Int(ceil(length(encryptedData) / blocktype.blocksize))
    decryptedData = Array{UInt8}(0)
    dataBlock = encryptedData[1 : blocktype.blocksize]
    xorvec = blocktype.decryptFunction(blocktype.initialVector, blocktype.key)
    dataBlock = dataBlock $ xorvec
    append!(decryptedData, dataBlock)
    for cnt in 2:blockCount
        if(cnt * blocktype.blocksize < length(blocktype.data))
            xorvec = encryptedData[((cnt-2) * blocktype.blocksize) + 1 : (cnt-1) * blocktype.blocksize]
            xorvec = blocktype.decryptFunction(xorvec, blocktype.key)
            dataBlock = encryptedData[((cnt-1) * blocktype.blocksize) + 1 : cnt * blocktype.blocksize]
            dataBlock = dataBlock $ xorvec
        else        
            xorvec = encryptedData[((cnt-2) * blocktype.blocksize) + 1 : (cnt-1) * blocktype.blocksize]
            xorvec = blocktype.decryptFunction(xorvec, blocktype.key)
            dataBlock = encryptedData[((cnt-1) * blocktype.blocksize) + 1 : end]
            dataBlock = dataBlock $ xorvec
        end
        append!(decryptedData, dataBlock)
    end
    decryptedData = decryptedData[1:length(blocktype.data)]
    return decryptedData
end

end
