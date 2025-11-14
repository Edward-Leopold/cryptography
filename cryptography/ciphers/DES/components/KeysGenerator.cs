using cryptography.Utilities;
using cryptography.ciphers.DES.constants;

namespace cryptography.ciphers.DES.components;

public static class KeysGenerator
{
    public static byte[][] GenerateRoundKeys(in byte[] key)
    {
        if (key == null)
        {
            throw new ArgumentNullException(nameof(key));
        }

        if (!(key.Length == 7 || key.Length == 8))
        {
            throw new ArgumentException("The key length must be 7 or 8 bytes, which corresponds to a length of 56 or 64 bits, respectively.");
        }
        
        byte[][] keys = new byte[16][];

        var keyCopy = (byte[])key.Clone();

        if (keyCopy.Length == 8)
        {
            foreach (byte b in keyCopy)
            {
                if (!CheckKeyByteStrength(b))
                {
                    Console.WriteLine("WARNING: Weak key detected");
                }
            }

            keyCopy = PBlock.Permutation(keyCopy, DesConstants.PC1, PBlock.BitsIndexingMode.HighToLow, 1);
        }

        byte[] c_0 = new byte[4];
        byte[] d_0 = new byte[4];
        for (int i = 0; i <= 27; ++i)
        {
            BitOperations.PlaceBitToPosition(ref keyCopy, ref c_0, (uint)i, (uint)i);
        }
        for (int i = 28; i <= 55; ++i)
        {
            BitOperations.PlaceBitToPosition(ref keyCopy, ref d_0, (uint)i, (uint)(i - 28));
        }

        var prevC = c_0;
        var prevD = d_0;
        for (int i = 0; i < 16; ++i)
        {
            byte[] c_i = (byte[])prevC.Clone();
            byte[] d_i = (byte[])prevD.Clone();
            BitOperations.LeftCyclicShift(c_i, DesConstants.LeftShiftTable[i], 28);
            BitOperations.LeftCyclicShift(d_i, DesConstants.LeftShiftTable[i], 28);
            
            byte[] cd = new byte[7];
            for (int t = 0; t < 28; ++t)
            {
                BitOperations.PlaceBitToPosition(ref c_i, ref cd, (uint)t, (uint)t);
            }
            for (int t = 28; t < 56; ++t)
            {
                BitOperations.PlaceBitToPosition(ref d_i, ref cd, (uint)(t - 28), (uint)t);
            }
            
            keys[i] = PBlock.Permutation(cd,  DesConstants.PC2, PBlock.BitsIndexingMode.HighToLow, 1);
            
            prevC = c_i;
            prevD = d_i;
        }
        
        return keys;
        
        bool CheckKeyByteStrength(byte keyByte)
        {
            int count = 0;
            for (int i = 0; i < 8; i++)
            {
                if ((keyByte & (1 << i)) != 0)
                    count++;
            }
            return (count % 2) == 1;
        }
    }
}