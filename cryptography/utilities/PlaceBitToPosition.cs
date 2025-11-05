namespace cryptography.Utilities;

public static class PlaceBitToPosition
{   
    /// <summary>High-to-Low bit indexing only! A bit with the lowest index will be in the leftest position</summary>
    public static void Place(ref readonly byte[] src, ref byte[] dest, uint srcBitPos, uint destBitPos)
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
}