using System.Text;
using cryptography.SymmetricContext;
using cryptography.ciphers.DEAL;
using Xunit.Abstractions;

namespace Tests.DEAL.results;

public class DealTests
{
    
    [Fact]
    public async Task Deal_Img_Test()
    {
        string baseDir = AppContext.BaseDirectory;
        string inPath = Path.Combine(baseDir, "../../../TestFiles/test.jpg"); 
        string outPathEnc = Path.Combine(baseDir, "../../../DEAL/results/encrypted/test_encrypted.jpg");
        string outPathDec = Path.Combine(baseDir, "../../../DEAL/results/decrypted/test_decrypted.jpg");

        if (!File.Exists(inPath)) 
            throw new FileNotFoundException("Исходный файл не найден по пути: " + Path.GetFullPath(inPath));

        byte[] key = new byte[32];
        var deal = new cryptography.ciphers.DEAL.DEAL();
        var context = new SymmetricContext(deal, key, EncryptionModes.PCBC, PaddingModes.PKCS7, blockSize: 16);

        await context.EncryptAsync(inPath, outPathEnc);
        await context.DecryptAsync(outPathEnc, outPathDec);

        byte[] originalBytes = await File.ReadAllBytesAsync(inPath);
        byte[] decryptedBytes = await File.ReadAllBytesAsync(outPathDec);

        Assert.Equal(originalBytes.Length, decryptedBytes.Length);
        Assert.Equal(originalBytes, decryptedBytes);

        byte[] encryptedBytes = await File.ReadAllBytesAsync(outPathEnc);
        Assert.NotEqual(originalBytes, encryptedBytes);
        
    }
    
    
}