using cryptography.interfaces;
using cryptography.Utilities;
using cryptography.ciphers.DES;

namespace cryptography.ciphers.DEAL.components;

public class KeysGenerator : IRoundKeysGenerator
{
    private readonly DES.DES _desForKeys;
    private static readonly byte[] FixedKey = new byte[8];

    public KeysGenerator()
    {
        _desForKeys = new DES.DES();
        _desForKeys.SetKey(FixedKey);
    }

    public byte[][] GenerateRoundKeys(in byte[] key)
    {
        int rounds = key.Length switch
        {
            16 => 6,
            24 => 6,
            32 => 8,
            _ => throw new ArgumentException("DEAL key must be 128, 192 or 256 bits (16, 24 or 32 bytes).")
        };

        byte[][] rk = new byte[rounds][];
        
        byte[][] kParts = new byte[key.Length / 8][];
        for (int i = 0; i < kParts.Length; i++)
        {
            kParts[i] = new byte[8];
            Buffer.BlockCopy(key, i * 8, kParts[i], 0, 8);
        }

        if (key.Length == 16)
        {
            rk[0] = _desForKeys.Encrypt(kParts[0]);
            rk[1] = _desForKeys.Encrypt(BitOperations.Xor(kParts[1], rk[0]));
            rk[2] = _desForKeys.Encrypt(BitOperations.Xor(BitOperations.Xor(kParts[0], GetMagic(1)), rk[1]));
            rk[3] = _desForKeys.Encrypt(BitOperations.Xor(BitOperations.Xor(kParts[1], GetMagic(2)), rk[2]));
            rk[4] = _desForKeys.Encrypt(BitOperations.Xor(BitOperations.Xor(kParts[0], GetMagic(4)), rk[3]));
            rk[5] = _desForKeys.Encrypt(BitOperations.Xor(BitOperations.Xor(kParts[1], GetMagic(8)), rk[4]));
        }
        else if (key.Length == 24)
        {
            rk[0] = _desForKeys.Encrypt(kParts[0]);
            rk[1] = _desForKeys.Encrypt(BitOperations.Xor(kParts[1], rk[0]));
            rk[2] = _desForKeys.Encrypt(BitOperations.Xor(kParts[2], rk[1]));
            rk[3] = _desForKeys.Encrypt(BitOperations.Xor(BitOperations.Xor(kParts[0], GetMagic(1)), rk[2]));
            rk[4] = _desForKeys.Encrypt(BitOperations.Xor(BitOperations.Xor(kParts[1], GetMagic(2)), rk[3]));
            rk[5] = _desForKeys.Encrypt(BitOperations.Xor(BitOperations.Xor(kParts[2], GetMagic(4)), rk[4]));
        }
        else if (key.Length == 32)
        {
            rk[0] = _desForKeys.Encrypt(kParts[0]);
            rk[1] = _desForKeys.Encrypt(BitOperations.Xor(kParts[1], rk[0]));
            rk[2] = _desForKeys.Encrypt(BitOperations.Xor(kParts[2], rk[1]));
            rk[3] = _desForKeys.Encrypt(BitOperations.Xor(kParts[3], rk[2]));
            rk[4] = _desForKeys.Encrypt(BitOperations.Xor(BitOperations.Xor(kParts[0], GetMagic(1)), rk[3]));
            rk[5] = _desForKeys.Encrypt(BitOperations.Xor(BitOperations.Xor(kParts[1], GetMagic(2)), rk[4]));
            rk[6] = _desForKeys.Encrypt(BitOperations.Xor(BitOperations.Xor(kParts[2], GetMagic(4)), rk[5]));
            rk[7] = _desForKeys.Encrypt(BitOperations.Xor(BitOperations.Xor(kParts[3], GetMagic(8)), rk[6]));
        }

        return rk;
    }
    
    private byte[] GetMagic(int i)
    {
        byte[] magic = new byte[8];
        int bitPos = i - 1;
        magic[7 - (bitPos / 8)] = (byte)(1 << (bitPos % 8));
        return magic;
    }
}