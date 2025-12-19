using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
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

public class PKCS7Padding : IPadding
{
    public byte[] AddPadding(byte[] data, int blockSize)
    {
        int paddingLength = blockSize - (data.Length % blockSize);
        byte[] result = new byte[data.Length + paddingLength];
        Array.Copy(data, result, data.Length);
        for (int i = data.Length; i < result.Length; i++)
        {
            result[i] = (byte)paddingLength;
        }
        return result;
    }

    public byte[] RemovePadding(byte[] data, int blockSize)
    {
        if (data.Length == 0) return data;
        int paddingLength = data[^1];
        if (paddingLength <= 0 || paddingLength > blockSize) return data;
        
        byte[] result = new byte[data.Length - paddingLength];
        Array.Copy(data, result, result.Length);
        return result;
    }
}

//
// public class ZerosPadding : IPadding
// {
//     public byte[] AddPadding(byte[] data, int blockSize)
//     {
//         int paddingLength = blockSize - (data.Length % blockSize);
//         if (paddingLength == 0) paddingLength = blockSize; // Всегда добавляем блок
//         byte[] result = new byte[data.Length + paddingLength];
//         Array.Copy(data, result, data.Length);
//         return result; // Остальное заполнено нулями по умолчанию
//     }
//     public byte[] RemovePadding(byte[] data, int blockSize) => data.TrimEnd((byte)0); // Упрощенно
// }

public class AnsiX923Padding : IPadding
{
    public byte[] AddPadding(byte[] data, int blockSize)
    {
        int paddingLength = blockSize - (data.Length % blockSize);
        byte[] result = new byte[data.Length + paddingLength];
        Array.Copy(data, result, data.Length);
        result[^1] = (byte)paddingLength; // Последний байт — длина
        return result;
    }
    public byte[] RemovePadding(byte[] data, int blockSize) => data[..^data[^1]];
}

public class Iso10126Padding : IPadding
{
    public byte[] AddPadding(byte[] data, int blockSize)
    {
        int paddingLength = blockSize - (data.Length % blockSize);
        byte[] result = new byte[data.Length + paddingLength];
        new Random().NextBytes(result); // Заполняем случайными числами
        Array.Copy(data, result, data.Length);
        result[^1] = (byte)paddingLength;
        return result;
    }
    public byte[] RemovePadding(byte[] data, int blockSize) => data[..^data[^1]];
}

// Контекст
public class SymmetricContext
{
    private readonly ISymmetricEncryption _algorithm;
    private readonly EncryptionModes _mode;
    private readonly IPadding _padding;
    private readonly byte[] _key;
    private readonly byte[]? _iv;
    private readonly int _blockSize;

    public SymmetricContext(
        ISymmetricEncryption algorithm,
        byte[] key,
        EncryptionModes mode,
        PaddingModes paddingMode,
        byte[]? iv = null,
        int blockSize = 8)
    {
        _algorithm = algorithm;
        _key = key;
        _mode = mode;
        _iv = iv;
        _blockSize = blockSize;
        _algorithm.SetKey(key);

        _padding = paddingMode switch
        {
            PaddingModes.PKCS7 => new PKCS7Padding(),
            // PaddingModes.Zeros => new ZerosPadding(),
            PaddingModes.ANSIX_923 => new AnsiX923Padding(),
            PaddingModes.ISO_10126 => new Iso10126Padding(),
            _ => throw new NotImplementedException()
        };
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
                        Array.Copy(paddedData, i * _blockSize, block, 0, _blockSize);
                        byte[] encrypted = _algorithm.Encrypt(block);
                        Array.Copy(encrypted, 0, result, i * _blockSize, _blockSize);
                    });
                    break;

                case EncryptionModes.CBC:
                    // CBC нельзя параллелить при шифровании
                    for (int i = 0; i < blockCount; i++)
                    {
                        byte[] block = new byte[_blockSize];
                        Array.Copy(paddedData, i * _blockSize, block, 0, _blockSize);
                        
                        byte[] xored = BitOperations.Xor(block, prevBlock);
                        prevBlock = _algorithm.Encrypt(xored);
                        
                        Array.Copy(prevBlock, 0, result, i * _blockSize, _blockSize);
                    }
                    break;

                case EncryptionModes.CTR:
                    // CTR можно параллелить полностью
                    Parallel.For(0, blockCount, i =>
                    {
                        byte[] counterBlock = (byte[])_iv.Clone();
                        // Увеличиваем счетчик (упрощенно: последний байт + i)
                        counterBlock[^1] = (byte)(counterBlock[^1] + i); 
                        
                        byte[] encryptedCounter = _algorithm.Encrypt(counterBlock);
                        
                        byte[] block = new byte[_blockSize];
                        Array.Copy(paddedData, i * _blockSize, block, 0, _blockSize);
                        
                        byte[] encrypted = BitOperations.Xor(block, encryptedCounter);
                        Array.Copy(encrypted, 0, result, i * _blockSize, _blockSize);
                    });
                    break;

                default:
                    throw new NotImplementedException($"Mode {_mode} is not implemented yet");
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
            byte[] prevBlock = (byte[])_iv.Clone();

            switch (_mode)
            {
                case EncryptionModes.ECB:
                    Parallel.For(0, blockCount, i =>
                    {
                        byte[] block = new byte[_blockSize];
                        Array.Copy(data, i * _blockSize, block, 0, _blockSize);
                        byte[] decrypted = _algorithm.Decrypt(block);
                        Array.Copy(decrypted, 0, resultPadded, i * _blockSize, _blockSize);
                    });
                    break;

                case EncryptionModes.CBC:
                    // CBC МОЖНО параллелить при дешифровании!
                    Parallel.For(0, blockCount, i =>
                    {
                        byte[] block = new byte[_blockSize];
                        Array.Copy(data, i * _blockSize, block, 0, _blockSize);
                        
                        byte[] decrypted = _algorithm.Decrypt(block);
                        
                        byte[] prevForThisBlock = (i == 0) ? _iv : data.Skip((i - 1) * _blockSize).Take(_blockSize).ToArray();
                        byte[] xored = BitOperations.Xor(decrypted, prevForThisBlock);
                        
                        Array.Copy(xored, 0, resultPadded, i * _blockSize, _blockSize);
                    });
                    break;

                case EncryptionModes.CTR:
                    // Дешифрование в CTR идентично шифрованию
                    return EncryptAsync(data).Result; 

                default:
                    throw new NotImplementedException();
            }

            return _padding.RemovePadding(resultPadded, _blockSize);
        });
    }
} 