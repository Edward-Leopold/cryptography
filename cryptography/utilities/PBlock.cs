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
        
        byte[] output = new byte[value.Length];
        byte[] input = new byte[value.Length];
        value.CopyTo(input, 0);
        
        if (bitIndexMode == BitsIndexingMode.HighToLow)
        {
            PermBitsInBytes(ref input);
        }
        
        if (bitIndexMode == BitsIndexingMode.LowToHigh)
        {
            Array.Reverse(input);
        }

        for (int i = 0, j = 0; i < permRule.Length && j < value.Length * 8; i++, j++)
        {   
            int pos = permRule[i] - start;
            int oldByteInd = pos / 8;
            int oldBitInd = pos % 8;
            int newByteInd = i / 8;
            int newBitInd = i % 8;

            if ( (input[oldByteInd] & (1 << oldBitInd)) != 0 )
            {
                output[newByteInd] |= (byte)(1 << newBitInd);
            } // вынести потом перестановку бита
        }

        if (bitIndexMode == BitsIndexingMode.HighToLow)
        {
            PermBitsInBytes(ref output);
        }
        
        if (bitIndexMode == BitsIndexingMode.LowToHigh)
        {
            Array.Reverse(output);
        }

        return output;
        
        void PermBitsInBytes(ref byte[] bytes)
        {
            for (int i = 0; i < bytes.Length; ++i)
            {
                bytes[i] = BitsPermutation.Permutate(bytes[i]);
            }
        }
    }
}