using cryptography.Utilities;

namespace Tests.Utilities;

public class BitOperationsTests
{
    [Theory]
    [InlineData(
        2, 
        28,
        new byte[] { 0b11000000, 0b00000000, 0b00000000, 0b00000000 },
        new byte[] { 0b00000000, 0b00000000, 0b00000000, 0b00110000 }
    )]
    [InlineData(
        1,  
        8,  
        new byte[] { 0b11000000 },
        new byte[] { 0b10000001 }  
    )]
    [InlineData(
        28, 
        28,
        new byte[] { 0b11000000, 0b00000000, 0b00000000, 0b00000000 },
        new byte[] { 0b11000000, 0b00000000, 0b00000000, 0b00000000 }  
    )]
    [InlineData(
        0, 
        28,
        new byte[] { 0b11000000, 0b00000000, 0b00000000, 0b00000000 },
        new byte[] { 0b11000000, 0b00000000, 0b00000000, 0b00000000 }  
    )]
    [InlineData(
        4, 
        12, 
        new byte[] { 0b11110100, 0b00000000 }, 
        new byte[] { 0b01000000, 0b11110000 } 
    )]
    public void BitOperations_LeftCyclicShift_Tests(
        int shift, int totalBits, byte[] input, byte[] expected)
    {
        BitOperations.LeftCyclicShift(input, shift, totalBits);

        // Assert
        Assert.Equal(expected, input);
    }
}