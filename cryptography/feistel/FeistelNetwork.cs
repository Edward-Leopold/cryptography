using cryptography.Utilities;
using cryptography.interfaces;

namespace cryptography.feistel;

public class FeistelNetwork
{
    private readonly IRoundKeysGenerator _keysGenerator;
    private readonly IRoundEncryption _roundEncryption;
    
    public FeistelNetwork(IRoundKeysGenerator keysGenerator, IRoundEncryption roundEncryption)
    {
        _keysGenerator =  keysGenerator;
        _roundEncryption = roundEncryption;
    }

    public byte[] Encrypt(in byte[] input, in byte[] key)
    {
        return ProcessFeistel(input, key, false);
    }

    public byte[] Decrypt(in byte[] input, in byte[] key)
    {
        return ProcessFeistel(input, key, true);
    }

    private byte[] ProcessFeistel(byte[] input, in byte[] key, bool isDecryption = false)
    {
        if (input.Length % 2 != 0)
        {
            throw new ArgumentException("Input size of bytes must be even");
        }
        
        int half = input.Length / 2;
        byte[] left = input[0..half];
        byte[] right = input[half..];
    
        var roundKeys = _keysGenerator.GenerateRoundKeys(key);
        if (isDecryption) Array.Reverse(roundKeys);
        foreach (var roundKey in roundKeys)
        {   
            byte[] fRes = _roundEncryption.EncryptRoundConversion(right, roundKey);
            byte[] newRight = BitOperations.Xor(left, fRes);
            left = right;
            right = newRight;
        }
        
        byte[] result = right.Concat(left).ToArray();
        return result;
    }
}