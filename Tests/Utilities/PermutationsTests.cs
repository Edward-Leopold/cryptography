using cryptography.Utilities;

namespace Tests.Utilities;

public class PermutationsTests
{
    [Theory]
    [InlineData(
        new byte[] { 0b11111110, 0b11111111, 0b11111111, 0b11111111 },
        new byte[] { 0b01111111, 0b11111111, 0b11111111, 0b11111111 }
    )]
    public void PBlock_LowToHigh_Tests(
        byte[] input, byte[] expected)
    {
        int[] pBlock =
        [
            16, 7, 20, 21,
            29, 12, 28, 17,
            1, 15, 23, 26,
            5, 18, 31, 10,
            2, 8, 24, 14,
            32, 27, 3, 9,
            19, 13, 30, 6,
            22, 11, 4, 25,
        ];

        byte[] output = Permutations.PermutateByTable(input, pBlock, Permutations.BitsIndexingMode.LowToHigh, 1);

        // Assert
        Assert.Equal(expected, output);
    }

    [Theory]
    [InlineData(
        new byte[] {0b11111111, 0b11111111, 0b11111111, 0b01111111 },
new byte[] { 0b11111111, 0b11111111, 0b11111111, 0b11111110 }
    )]
    public void PBlock_HighToLow_Tests(
        byte[] input, byte[] expected)
    {
        int[] pBlock = [
            16, 7, 20, 21,
            29, 12, 28, 17,
            1, 15, 23, 26, 
            5, 18, 31, 10,
            2, 8, 24, 14, 
            32, 27, 3, 9,
            19, 13, 30, 6,
            22, 11, 4, 25,
        ]; 
    
        byte[] output = Permutations.PermutateByTable(input, pBlock, Permutations.BitsIndexingMode.HighToLow, 1);
    
        // Assert
        Assert.Equal(expected, output);
    }
}