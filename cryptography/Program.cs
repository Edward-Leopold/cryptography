using cryptography.Utilities; 

class Program
{
    static void Main()
    {
        try
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
            
            // byte[] input1 = [ 0b10101010, 0b01010101, 0b11001100, 0b00110011 ];
            // byte[] input2 = [ 0b11111111, 0b11111111, 0b11111111, 0b01111111 ];
            byte[] input3 = [ 0b11111110, 0b11111111, 0b11111111, 0b11111111 ];
            
            byte[] output = Permutations.PermutateByTable(input3, pBlock, Permutations.BitsIndexingMode.LowToHigh, 1);
                
            foreach (byte b in input3)
            {
                Console.Write(Convert.ToString(b, 2).PadLeft(8, '0') + " ");
            }
            Console.WriteLine();
            foreach (byte b in output)
            {
                Console.Write(Convert.ToString(b, 2).PadLeft(8, '0') + " ");
            }
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            throw;
        }
    }
}