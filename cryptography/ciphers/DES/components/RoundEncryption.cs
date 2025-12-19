using cryptography.interfaces;
using cryptography.Utilities;
using cryptography.ciphers.DES.constants;

namespace cryptography.ciphers.DES.components;

public class RoundEncryption : IRoundEncryption
{
    public byte[] EncryptRoundConversion(byte[] inputBlock, byte[] roundKey)
    {
        var inputExtended = Permutations.PermutateByTable(inputBlock, DesConstants.E, Permutations.BitsIndexingMode.HighToLow, 1);
        var inputXored = BitOperations.Xor(roundKey, inputExtended);
        var blockTransformedWithS = MakeSBlockTransformation(inputXored);
        var output = Permutations.PermutateByTable(blockTransformedWithS, DesConstants.P, Permutations.BitsIndexingMode.HighToLow, 1);
        
        return output;
    }

    private byte[] MakeSBlockTransformation(byte[] xored)
    {
        if (xored.Length != 6)
        {
            throw new ArgumentException("Size of xored block must be 6 bytes");
        }
        
        ulong input48Bit = 0;
        for (int i = 0; i < 6; i++) {
            input48Bit = (input48Bit << 8) | xored[i];
        }
        
        ulong output32Bit = 0;
        for (int i = 0; i < 8; i++) {
            int shift = (7 - i) * 6;
            ulong bits6 = (input48Bit >> shift) & 0x3F; 

            ulong row = ((bits6 & 0x20) >> 4) | (bits6 & 0x01);
            ulong column = ((bits6 >> 1) & 0x0F);

            output32Bit = (output32Bit << 4) | (DesConstants.S[i][(int)row][(int)column] & 0x0F);
        }
        
        byte[] result = new byte[4]; 
        result[0] = (byte)((output32Bit >> 24) & 0xFF);
        result[1] = (byte)((output32Bit >> 16) & 0xFF);
        result[2] = (byte)((output32Bit >> 8) & 0xFF);
        result[3] = (byte)(output32Bit & 0xFF);

        return result;
    }
}