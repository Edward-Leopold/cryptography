namespace cryptography.Utilities;



 public static class PBlock
{   
    public enum BitsIndexingMode
    {
        LowToHigh,
        HighToLow
    }
    
    public static byte[] Permutation(byte[] value, int[] permRule, BitsIndexingMode bitIndexMode, int start)
    {
        if (value == null || permRule == null || permRule.Length == 0 || value.Length == 0)
        {
            throw new ArgumentNullException();
        }
        if (start != 1 && start != 0)
        {
            throw new Exception("start index must be 0 or 1");
        }
        if (permRule.Min() < start || permRule.Max() >= value.Length * 8 + start)
        {
            throw new Exception("position in P-block table is out of range");
        }
        
        int outputLength = permRule.Length / 8 + (permRule.Length % 8 == 0 ? 0 : 1); 
        byte[] output = new byte[outputLength];
        byte[] input = new byte[value.Length];
        value.CopyTo(input, 0);
        
        if (bitIndexMode == BitsIndexingMode.LowToHigh)
        {   
            PermBitsInBytes(ref input);
            Array.Reverse(input);
        }

        for (int i = 0, j = 0; i < permRule.Length && j < value.Length * 8; i++, j++)
        {   
            int pos = permRule[i] - start;
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