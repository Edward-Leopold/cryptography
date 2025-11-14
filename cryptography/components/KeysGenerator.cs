using cryptography.Utilities;

namespace cryptography.components;

public static class KeysGenerator
{
    public static byte[][] GenerateKeys(in byte[] key)
    {
        if (key == null)
        {
            throw new ArgumentNullException(nameof(key));
        }

        if (!(key.Length == 7 || key.Length == 8))
        {
            throw new ArgumentException("The key length must be 7 or 8 bytes, which corresponds to a length of 56 or 64 bits, respectively.");
        }
        
        int[] PC_1 = [
            57, 49, 41, 33, 25, 17, 9,
            1,  58, 50, 42, 34, 26, 18,
            10, 2,  59, 51, 43, 35, 27,
            19, 11, 3,  60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7,  62, 54, 46, 38, 30, 22,
            14, 6,  61, 53, 45, 37, 29,
            21, 13, 5,  28, 20, 12, 4
        ];
        
        int[] PC_2 = [
            14, 17, 11, 24, 1,  5,
            3,  28, 15, 6,  21, 10,
            23, 19, 12, 4,  26, 8,
            16, 7,  27, 20, 13, 2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32
        ];

        int[] leftShiftTable = [
            1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
        ];
        
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

            // try
            // {
            keyCopy = PBlock.Permutation(keyCopy, PC_1, PBlock.BitsIndexingMode.HighToLow, 1);
            // }
            // catch (Exception e)
            // {
            //     Console.WriteLine(e);
            //     throw;
            // }
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
            BitOperations.LeftCyclicShift(c_i, leftShiftTable[i], 28);
            BitOperations.LeftCyclicShift(d_i, leftShiftTable[i], 28);
            
            byte[] cd = new byte[7];
            for (int t = 0; t < 28; ++t)
            {
                BitOperations.PlaceBitToPosition(ref c_i, ref cd, (uint)t, (uint)t);
            }
            for (int t = 28; t < 56; ++t)
            {
                BitOperations.PlaceBitToPosition(ref d_i, ref cd, (uint)(t - 28), (uint)t);
            }
            
            keys[i] = PBlock.Permutation(cd,  PC_2, PBlock.BitsIndexingMode.HighToLow, 1);
            
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