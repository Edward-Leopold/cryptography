namespace cryptography.Utilities;

public static class BitsPermutation
{
    public static byte Permutate(byte input)
    {
        byte output = 0;
        for (int i = 0; i < 8; ++i)
        {
            if (((1 << (7 - i)) & input) != 0)
            {
                output |= (byte)(1 << i);    
            }
        }
        return output;
    }
}