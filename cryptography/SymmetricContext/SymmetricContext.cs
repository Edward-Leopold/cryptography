using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.IO;
using cryptography.interfaces;
using cryptography.Utilities;

namespace cryptography.SymmetricContext;

public enum EncryptionModes { ECB, CBC, PCBC, CFB, OFB, CTR, RandomDelta }
public enum PaddingModes { Zeros, ANSIX_923, PKCS7, ISO_10126 }

public interface IPadding
{
    byte[] AddPadding(byte[] data, int blockSize);
    byte[] RemovePadding(byte[] data, int blockSize);
}

#region Padding Implementations

public class ZerosPadding : IPadding
{
    public byte[] AddPadding(byte[] data, int blockSize)
    {
        int paddingLength = blockSize - (data.Length % blockSize);
        if (paddingLength == blockSize && data.Length > 0) return data; 

        byte[] result = new byte[data.Length + paddingLength];
        Array.Copy(data, result, data.Length);
        return result;
    }

    public byte[] RemovePadding(byte[] data, int blockSize)
    {
        int i = data.Length - 1;
        while (i >= 0 && data[i] == 0)
        {
            i--;
        }
        
        byte[] result = new byte[i + 1];
        Array.Copy(data, result, i + 1);
        return result;
    }
}

public class ANSIX923Padding : IPadding
{
    public byte[] AddPadding(byte[] data, int blockSize)
    {
        int paddingLength = blockSize - (data.Length % blockSize);
        byte[] result = new byte[data.Length + paddingLength];
        Array.Copy(data, result, data.Length);
        result[^1] = (byte)paddingLength;
        return result;
    }
    public byte[] RemovePadding(byte[] data, int blockSize)
    {
        int len = data[^1];
        return data[..^len];
    }
}

public class PKCS7Padding : IPadding
{
    public byte[] AddPadding(byte[] data, int blockSize)
    {
        int paddingLength = blockSize - (data.Length % blockSize);
        byte[] result = new byte[data.Length + paddingLength];
        Array.Copy(data, result, data.Length);
        for (int i = data.Length; i < result.Length; i++) result[i] = (byte)paddingLength;
        return result;
    }
    public byte[] RemovePadding(byte[] data, int blockSize) => data[..^data[^1]];
}

public class ISO10126Padding : IPadding
{
    public byte[] AddPadding(byte[] data, int blockSize)
    {
        int paddingLength = blockSize - (data.Length % blockSize);
        byte[] result = new byte[data.Length + paddingLength];
        new Random().NextBytes(result);
        Array.Copy(data, result, data.Length);
        result[^1] = (byte)paddingLength;
        return result;
    }
    public byte[] RemovePadding(byte[] data, int blockSize) => data[..^data[^1]];
}

#endregion

public class SymmetricContext
{
    private readonly ISymmetricEncryption _algorithm;
    private readonly EncryptionModes _mode;
    private readonly IPadding _padding;
    private readonly byte[] _key;
    private readonly byte[] _iv;
    private readonly int _blockSize;

    public SymmetricContext(
        ISymmetricEncryption algorithm,
        byte[] key,
        EncryptionModes mode,
        PaddingModes paddingMode,
        byte[]? iv = null,
        int blockSize = 8)
    {
        _algorithm = algorithm ?? throw new ArgumentNullException(nameof(algorithm));
        _key = key;
        _mode = mode;
        _blockSize = blockSize;
        _iv = iv ?? new byte[_blockSize]; 
        _algorithm.SetKey(key);

        _padding = paddingMode switch
        {
            PaddingModes.PKCS7 => new PKCS7Padding(),
            PaddingModes.Zeros => new ZerosPadding(),
            PaddingModes.ANSIX_923 => new ANSIX923Padding(),
            PaddingModes.ISO_10126 => new ISO10126Padding(),
            _ => throw new NotImplementedException()
        };
    }
    
    private byte[] GetCounterBlock(byte[] iv, int iteration)
    {
        byte[] counter = (byte[])iv.Clone();
        long overflow = iteration;
        for (int i = counter.Length - 1; i >= 0 && overflow > 0; i--)
        {
            long val = counter[i] + overflow;
            counter[i] = (byte)(val & 0xFF);
            overflow = val >> 8;
        }
        return counter;
    }

    public async Task EncryptAsync(string inputFilePath, string outputFilePath)
    {
        byte[] data = await File.ReadAllBytesAsync(inputFilePath);
        byte[] result = await EncryptAsync(data);
        await File.WriteAllBytesAsync(outputFilePath, result);
    }

    public async Task DecryptAsync(string inputFilePath, string outputFilePath)
    {
        byte[] data = await File.ReadAllBytesAsync(inputFilePath);
        byte[] result = await DecryptAsync(data);
        await File.WriteAllBytesAsync(outputFilePath, result);
    }

    public async Task<byte[]> EncryptAsync(byte[] data)
    {
        return await Task.Run(() =>
        {
            byte[] paddedData = _padding.AddPadding(data, _blockSize);
            int blockCount = paddedData.Length / _blockSize;
            byte[] result = new byte[paddedData.Length];
            byte[] prevBlock = (byte[])_iv.Clone();

            switch (_mode)
            {
                case EncryptionModes.ECB:
                    Parallel.For(0, blockCount, i =>
                    {
                        byte[] block = new byte[_blockSize];
                        Buffer.BlockCopy(paddedData, i * _blockSize, block, 0, _blockSize);
                        byte[] encrypted = _algorithm.Encrypt(block);
                        Buffer.BlockCopy(encrypted, 0, result, i * _blockSize, _blockSize);
                    });
                    break;

                case EncryptionModes.CBC:
                    for (int i = 0; i < blockCount; i++)
                    {
                        byte[] block = new byte[_blockSize];
                        Buffer.BlockCopy(paddedData, i * _blockSize, block, 0, _blockSize);
                        byte[] xored = BitOperations.Xor(block, prevBlock);
                        prevBlock = _algorithm.Encrypt(xored);
                        Buffer.BlockCopy(prevBlock, 0, result, i * _blockSize, _blockSize);
                    }
                    break;
                
                case EncryptionModes.PCBC:
                    {
                        for (int i = 0; i < blockCount; i++)
                        {
                            byte[] block = new byte[_blockSize];
                            Buffer.BlockCopy(paddedData, i * _blockSize, block, 0, _blockSize);
                            byte[] xored = BitOperations.Xor(block, prevBlock);
                            byte[] encrypted = _algorithm.Encrypt(xored);
                
                            Buffer.BlockCopy(encrypted, 0, result, i * _blockSize, _blockSize);
                            prevBlock = BitOperations.Xor(block, encrypted); 
                        }
                    }
                    break;

                case EncryptionModes.CTR:
                    Parallel.For(0, blockCount, i =>
                    {
                        byte[] counterBlock = GetCounterBlock(_iv, i);
                        byte[] keyStream = _algorithm.Encrypt(counterBlock);
        
                        byte[] block = new byte[_blockSize];
                        int bytesToCopy = Math.Min(_blockSize, paddedData.Length - i * _blockSize);
                        Buffer.BlockCopy(paddedData, i * _blockSize, block, 0, bytesToCopy);
        
                        byte[] encrypted = BitOperations.Xor(block, keyStream);
                        Buffer.BlockCopy(encrypted, 0, result, i * _blockSize, _blockSize);
                    });
                    break;
                
                case EncryptionModes.CFB:
                    {
                        byte[] feedback = (byte[])_iv.Clone();
                        for (int i = 0; i < blockCount; i++)
                        {
                            byte[] keystream = _algorithm.Encrypt(feedback);
                            byte[] block = new byte[_blockSize];
                            Buffer.BlockCopy(paddedData, i * _blockSize, block, 0, _blockSize);
                
                            byte[] cipherBlock = BitOperations.Xor(block, keystream);
                            Buffer.BlockCopy(cipherBlock, 0, result, i * _blockSize, _blockSize);
                
                            feedback = cipherBlock; 
                        }
                    }
                    break;

                case EncryptionModes.OFB:
                    {
                        byte[] feedback = (byte[])_iv.Clone();
                        for (int i = 0; i < blockCount; i++)
                        {
                            feedback = _algorithm.Encrypt(feedback);
                            byte[] block = (byte[])_iv.Clone();
                            Buffer.BlockCopy(paddedData, i * _blockSize, block, 0, _blockSize);
                            byte[] encrypted = BitOperations.Xor(block, feedback);
                
                            Buffer.BlockCopy(encrypted, 0, result, i * _blockSize, _blockSize);
                        }
                    }
                    break;

                case EncryptionModes.RandomDelta:
                    {
                        byte[] delta = _iv.Skip(_blockSize / 2).Concat(new byte[_blockSize / 2]).Take(_blockSize).ToArray();
            
                        Parallel.For(0, blockCount, i =>
                        {
                            byte[] currentIv = (byte[])_iv.Clone();
                            for(int d = 0; d < i; d++) currentIv = BitOperations.Xor(currentIv, delta);
                
                            byte[] block = (byte[])_iv.Clone();
                            Buffer.BlockCopy(paddedData, i * _blockSize, block, 0, _blockSize);
                            byte[] xored = BitOperations.Xor(block, currentIv);
                            byte[] encrypted = _algorithm.Encrypt(xored);
                            Buffer.BlockCopy(encrypted, 0, result, i * _blockSize, _blockSize);
                        });
                    }
                    break;

                default:
                    throw new NotImplementedException($"Mode {_mode} not implemented");
            }
            return result;
        });
    }

    public async Task<byte[]> DecryptAsync(byte[] data)
    {
        return await Task.Run(() =>
        {
            int blockCount = data.Length / _blockSize;
            byte[] resultPadded = new byte[data.Length];

            switch (_mode)
            {
                case EncryptionModes.ECB:
                    Parallel.For(0, blockCount, i =>
                    {
                        byte[] block = new byte[_blockSize];
                        Buffer.BlockCopy(data, i * _blockSize, block, 0, _blockSize);
                        byte[] decrypted = _algorithm.Decrypt(block);
                        Buffer.BlockCopy(decrypted, 0, resultPadded, i * _blockSize, _blockSize);
                    });
                    break;

                case EncryptionModes.CBC:
                    Parallel.For(0, blockCount, i =>
                    {
                        byte[] block = new byte[_blockSize];
                        Buffer.BlockCopy(data, i * _blockSize, block, 0, _blockSize);
                        byte[] decrypted = _algorithm.Decrypt(block);
                        
                        byte[] prev = (i == 0) ? _iv : data.Skip((i - 1) * _blockSize).Take(_blockSize).ToArray();
                        byte[] xored = BitOperations.Xor(decrypted, prev);
                        Buffer.BlockCopy(xored, 0, resultPadded, i * _blockSize, _blockSize);
                    });
                    break;
                
                case EncryptionModes.PCBC:
                    {
                        byte[] prevBlock = (byte[])_iv.Clone();
                        for (int i = 0; i < blockCount; i++)
                        {
                            byte[] block = new byte[_blockSize];
                            Buffer.BlockCopy(data, i * _blockSize, block, 0, _blockSize);
                            byte[] decrypted = _algorithm.Decrypt(block);
                            byte[] plain = BitOperations.Xor(decrypted, prevBlock);
                
                            Buffer.BlockCopy(plain, 0, resultPadded, i * _blockSize, _blockSize);
                            prevBlock = BitOperations.Xor(plain, block);
                        }
                    }
                    break;

                case EncryptionModes.CTR:
                    Parallel.For(0, blockCount, i =>
                    {
                        byte[] counterBlock = GetCounterBlock(_iv, i);
                        byte[] keyStream = _algorithm.Encrypt(counterBlock);
        
                        byte[] block = new byte[_blockSize];
                        Buffer.BlockCopy(data, i * _blockSize, block, 0, _blockSize);
        
                        byte[] decrypted = BitOperations.Xor(block, keyStream);
                        Buffer.BlockCopy(decrypted, 0, resultPadded, i * _blockSize, _blockSize);
                    });
                    break;
                
                case EncryptionModes.CFB:
                    {
                        Parallel.For(0, blockCount, i =>
                        {
                            byte[] block = new byte[_blockSize];
                            Buffer.BlockCopy(data, i * _blockSize, block, 0, _blockSize);
                
                            byte[] prevCipherBlock;
                            if (i == 0)
                            {
                                prevCipherBlock = _iv;
                            }
                            else
                            {
                                prevCipherBlock = new byte[_blockSize];
                                Buffer.BlockCopy(data, (i - 1) * _blockSize, prevCipherBlock, 0, _blockSize);
                            }

                            byte[] keystream = _algorithm.Encrypt(prevCipherBlock);
                            byte[] plain = BitOperations.Xor(block, keystream);
                            Buffer.BlockCopy(plain, 0, resultPadded, i * _blockSize, _blockSize);
                        });
                    }
                    break;

                case EncryptionModes.OFB:
                    {
                        byte[] feedback = (byte[])_iv.Clone();
                        for (int i = 0; i < blockCount; i++)
                        {
                            feedback = _algorithm.Encrypt(feedback);
                            byte[] block = new byte[_blockSize];
                            Buffer.BlockCopy(data, i * _blockSize, block, 0, _blockSize);
                            byte[] plain = BitOperations.Xor(block, feedback);
                            Buffer.BlockCopy(plain, 0, resultPadded, i * _blockSize, _blockSize);
                        }
                    }
                    break;

                case EncryptionModes.RandomDelta:
                    {
                        byte[] delta = _iv.Skip(_blockSize / 2).Concat(new byte[_blockSize / 2]).Take(_blockSize).ToArray();
                        Parallel.For(0, blockCount, i =>
                        {
                            byte[] currentIv = (byte[])_iv.Clone();
                            for(int d = 0; d < i; d++) currentIv = BitOperations.Xor(currentIv, delta);
                
                            byte[] block = new byte[_blockSize];
                            Buffer.BlockCopy(data, i * _blockSize, block, 0, _blockSize);
                            byte[] decrypted = _algorithm.Decrypt(block);
                            byte[] plain = BitOperations.Xor(decrypted, currentIv);
                            Buffer.BlockCopy(plain, 0, resultPadded, i * _blockSize, _blockSize);
                        });
                    }
                    break;

                default:
                    throw new NotImplementedException();
            }
            return _padding.RemovePadding(resultPadded, _blockSize);
        });
    }
}