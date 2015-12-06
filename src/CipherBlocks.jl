
include("Cryptic.jl")

module CipherBlocks

using Cryptic.AES

export ECB, CBC, CFB, encrypt, decrypt

type ECB 
    encryptionType
end

type CBC
    encryptionType
    initialVector::Array{UInt8}
end

type CFB
    encryptionType
    initialVector::Array{UInt8}
end

function encrypt(blocktype::CipherBlocks.ECB)
    blocksizeinbytes = Int(blocktype.encryptionType.bits / 8)
    databuffer = blocktype.encryptionType.buffer
    blockCount = Int(ceil(length(databuffer) / blocksizeinbytes))
    if(typeof(blocktype.encryptionType) == AES256)
        key = blocktype.encryptionType.enckey
    else
        key = blocktype.encryptionType.key
    end
    encryptedData = Array{UInt8}(0)
    for cnt in 1:blockCount
        if(cnt * blocksizeinbytes < length(databuffer))
            dataBlock = databuffer[((cnt-1) * blocksizeinbytes) + 1 : cnt * blocksizeinbytes]
         else
            dataBlock = databuffer[((cnt-1) * blocksizeinbytes) + 1 : end]
            append!(dataBlock, [1;zeros(UInt8, (blocksizeinbytes-length(dataBlock)-1))])
        end
        append!(encryptedData, blocktype.encryptionType.encrypt(dataBlock, key))
    end
    blocktype.encryptionType.buffer = encryptedData
end

function decrypt(blocktype::CipherBlocks.ECB)
    blocksizeinbytes = Int(blocktype.encryptionType.bits / 8)
    databuffer = blocktype.encryptionType.buffer
    blockCount = Int(ceil(length(databuffer) / blocksizeinbytes))
    if(typeof(blocktype.encryptionType) == AES256)
        key = blocktype.encryptionType.deckey
    else
        key = blocktype.encryptionType.key
    end
    decryptedData = Array{UInt8}(0)
    for cnt in 1:blockCount
        dataBlock = databuffer[((cnt-1) * blocksizeinbytes) + 1 : cnt * blocksizeinbytes]
        append!(decryptedData, blocktype.encryptionType.decrypt(dataBlock, key))
    end
    blocktype.encryptionType.buffer = removePadding!(decryptedData)
end

function encrypt(blocktype::CipherBlocks.CBC)
    blocksizeinbytes = Int(blocktype.encryptionType.bits / 8)
    databuffer = blocktype.encryptionType.buffer
    blockCount = Int(ceil(length(databuffer) / blocksizeinbytes))
    if(typeof(blocktype.encryptionType) == AES256)
        key = blocktype.encryptionType.enckey
    else
        key = blocktype.encryptionType.key
    end
    encryptedData = Array{UInt8}(0)
    dataBlock = databuffer[1 : blocksizeinbytes]
    dataBlock = dataBlock $ blocktype.initialVector
    encryptedBlock = blocktype.encryptionType.encrypt(dataBlock, key)
    append!(encryptedData, encryptedBlock)
    for cnt in 2:blockCount
        if(cnt * blocksizeinbytes < length(databuffer))
            dataBlock = databuffer[((cnt-1) * blocksizeinbytes) + 1 : cnt * blocksizeinbytes]
            dataBlock $= encryptedBlock
        else            
            dataBlock = databuffer[((cnt-1) * blocksizeinbytes) + 1 : end]
            append!(dataBlock, [1;zeros(UInt8, (blocksizeinbytes-length(dataBlock)-1))])
            dataBlock $= encryptedBlock
        end
        encryptedBlock = blocktype.encryptionType.encrypt(dataBlock, key)
        append!(encryptedData, encryptedBlock)
    end
    blocktype.encryptionType.buffer = encryptedData
end

function decrypt(blocktype::CipherBlocks.CBC)
    blocksizeinbytes = Int(blocktype.encryptionType.bits / 8)
    databuffer = blocktype.encryptionType.buffer
    blockCount = Int(ceil(length(databuffer) / blocksizeinbytes))
    if(typeof(blocktype.encryptionType) == AES256)
        key = blocktype.encryptionType.deckey
    else
        key = blocktype.encryptionType.key
    end
    decryptedData = Array{UInt8}(0)
    dataBlock = databuffer[1 : blocksizeinbytes]
    dataBlock = blocktype.encryptionType.decrypt(dataBlock, key) $ blocktype.initialVector
    append!(decryptedData, dataBlock)
    for cnt in 2:blockCount
        dataBlock = databuffer[((cnt-1) * blocksizeinbytes)+1 : cnt * blocksizeinbytes]
        xorvec = databuffer[((cnt-2) * blocksizeinbytes)+1 : (cnt-1) * blocksizeinbytes]
        dataBlock = blocktype.encryptionType.decrypt(dataBlock, key) $ xorvec
        append!(decryptedData, dataBlock)
    end
    blocktype.encryptionType.buffer = removePadding!(decryptedData)
end

function encrypt(blocktype::CipherBlocks.CFB)
    blocksizeinbytes = Int(blocktype.encryptionType.bits / 8)
    databuffer = blocktype.encryptionType.buffer
    blockCount = Int(ceil(length(databuffer) / blocksizeinbytes))
    if(typeof(blocktype.encryptionType) == AES256)
        key = blocktype.encryptionType.enckey
    else
        key = blocktype.encryptionType.key
    end
    encryptedData = Array{UInt8}(0)
    dataBlock = databuffer[1 : blocktype.blocksize]
    xorvec = blocktype.encryptionType.encrypt(blocktype.initialVector, key)
    dataBlock = dataBlock $ xorvec
    append!(encryptedData, dataBlock)
    for cnt in 2:blockCount
        if(cnt * blocksizeinbytes < length(databuffer))
            xorvec = blocktype.encryptionType.encrypt(dataBlock, key)
            dataBlock = databuffer[((cnt-1) * blocksizeinbytes) + 1 : cnt * blocksizeinbytes]
            dataBlock = dataBlock $ xorvec
        else     
            xorvec = blocktype.encryptFunction(dataBlock, key)       
            dataBlock = databuffer[((cnt-1) * blocksizeinbytes) + 1 : end]
            append!(dataBlock, [1;zeros(UInt8, (blocksizeinbytes-length(dataBlock)-1))])
            dataBlock = dataBlock $ xorvec
        end
        append!(encryptedData, dataBlock)
    end
    blocktype.encryptionType.buffer = encryptedData
end

function decrypt(blocktype::CipherBlocks.CFB)
    blocksizeinbytes = Int(blocktype.encryptionType.bits / 8)
    databuffer = blocktype.encryptionType.buffer
    blockCount = Int(ceil(length(databuffer) / blocksizeinbytes))
    if(typeof(blocktype.encryptionType) == AES256)
        key = blocktype.encryptionType.deckey
    else
        key = blocktype.encryptionType.key
    end
    decryptedData = Array{UInt8}(0)
    dataBlock = databuffer[1 : blocksizeinbytes]
    xorvec = blocktype.encryptionType.decrypt(blocktype.initialVector, key)
    dataBlock = dataBlock $ xorvec
    append!(decryptedData, dataBlock)
    for cnt in 2:blockCount
        xorvec = databuffer[((cnt-2) * blocksizeinbytes) + 1 : (cnt-1) * blocksizeinbytes]
        xorvec = blocktype.encryptionType.decrypt(xorvec, key)
        dataBlock = databuffer[((cnt-1) * blocksizeinbytes) + 1 : cnt * blocksizeinbytes]
        dataBlock = dataBlock $ xorvec
        append!(decryptedData, dataBlock)
    end
    blocktype.encryptionType.buffer = removePadding!(decryptedData)
end

function removePadding!(arr::Array{UInt8})
    startPadding = findlast(arr,1)
    if(startPadding >= length(arr) || startPadding == 0)
        return arr
    elseif findfirst(arr[startPadding+1:end]) == 0
        return arr[1:startPadding-1]
    end
    return arr
end

end
