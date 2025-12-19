namespace cryptography.Utilities;



 public static class Permutations
{   
    public enum BitsIndexingMode
    {
        LowToHigh,
        HighToLow
    }
    
    public static byte[] PermutateByTable(byte[] value, int[] permTable, BitsIndexingMode bitIndexMode, int start)
    {
        if (value == null || permTable == null || permTable.Length == 0 || value.Length == 0)
        {
            throw new ArgumentNullException();
        }
        if (start != 1 && start != 0)
        {
            throw new Exception("start index must be 0 or 1");
        }
        if (permTable.Min() < start || permTable.Max() >= value.Length * 8 + start)
        {
            throw new Exception("position in P-block table is out of range");
        }
        
        int outputLength = permTable.Length / 8 + (permTable.Length % 8 == 0 ? 0 : 1); 
        byte[] output = new byte[outputLength];
        byte[] input = new byte[value.Length];
        value.CopyTo(input, 0);
        
        if (bitIndexMode == BitsIndexingMode.LowToHigh)
        {   
            PermBitsInBytes(ref input);
            Array.Reverse(input);
        }

        for (int i = 0; i < permTable.Length; i++)
        {   
            int pos = permTable[i] - start;
            BitOperations.PlaceBitToPosition(ref input, ref output, (uint)pos, (uint)i);
        }
        
        if (bitIndexMode == BitsIndexingMode.LowToHigh)
        {
            PermBitsInBytes(ref output);
            Array.Reverse(output);
        }

        return output;
        
        void PermBitsInBytes(ref byte[] bytes)
        {
            for (int i = 0; i < bytes.Length; ++i)
            {
                bytes[i] = BitOperations.Permutate(bytes[i]);
            }
        }
    }
}