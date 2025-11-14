namespace cryptography.Utilities;

public static class BitOperations
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
    
    /// <summary>High-to-Low bit indexing only! A bit with the lowest index will be in the leftest position</summary>
    public static void PlaceBitToPosition(ref readonly byte[] src, ref byte[] dest, uint srcBitPos, uint destBitPos)
    {
        uint srcByteIndex = srcBitPos / 8;
        uint srcBitIndex = srcBitPos % 8;
        uint destByteIndex = destBitPos / 8;
        uint destBitIndex = destBitPos % 8;
        
        dest[destByteIndex] &= (byte)~(1 << (7 - (int)destBitIndex));
        if ( (src[srcByteIndex] & (1 << (7 - (int)srcBitIndex))) != 0 )
        {
            dest[destByteIndex] |= (byte)(1 << (7 - (int)destBitIndex));
        } 
    }
    
    /// <summary>High-to-Low bit indexing only! A bit with the lowest index will be in the leftest position</summary>
    public static void LeftCyclicShift(byte[] data, int shift, int totalBits)
    {
        shift %= totalBits;
        if (shift == 0) return;
        
        byte[] temp = new byte[data.Length];
        Array.Copy(data, temp, data.Length);
        for (int i = 0; i < totalBits; i++)
        {
            int srcBitPos = (i + shift) % totalBits;
            int destBitPos = i;
        
            int srcByteIndex = srcBitPos / 8;
            int srcBitIndex = srcBitPos % 8;
            bool bitValue = (temp[srcByteIndex] & (1 << (7 - srcBitIndex))) != 0;
        
            int destByteIndex = destBitPos / 8;
            int destBitIndex = destBitPos % 8;
        
            if (bitValue)
                data[destByteIndex] |= (byte)(1 << (7 - destBitIndex));
            else
                data[destByteIndex] &= (byte)~(1 << (7 - destBitIndex));
        }
    }
}