using System.Text;
using cryptography.ciphers.TripleDES;
using cryptography.SymmetricContext;
using Xunit;

namespace Tests.TripleDES;

public class TripleDESTests
{
    private readonly string _baseDir = AppContext.BaseDirectory;

    [Theory]
    [InlineData("test.txt", EncryptionModes.CBC, PaddingModes.PKCS7)]
    [InlineData("test.jpg", EncryptionModes.CTR, PaddingModes.ISO_10126)]
    [InlineData("test.pdf", EncryptionModes.CFB, PaddingModes.ANSIX_923)]
    public async Task TripleDes_FileProcessing_ShouldPreserveData(string fileName, EncryptionModes mode, PaddingModes padding)
    {
        string fileNameOnly = Path.GetFileNameWithoutExtension(fileName); 
        string extension = Path.GetExtension(fileName);                  
        string inPath = Path.GetFullPath(Path.Combine(_baseDir, "../../../TestFiles/", fileName));
        string encPath = Path.Combine(_baseDir, "../../../TripleDES/results/encrypted/", $"{fileNameOnly}_encrypted{extension}");
        string decPath = Path.Combine(_baseDir, "../../../TripleDES/results/decrypted/", $"{fileNameOnly}_decrypted{extension}");

        if (!File.Exists(inPath)) return; 

        byte[] key = Encoding.UTF8.GetBytes("tripledes_strong_key_24b"); 
        byte[] iv = Encoding.UTF8.GetBytes("iv_8byte"); 

        var tdes = new cryptography.ciphers.TripleDES.TripleDES();
        var context = new SymmetricContext(tdes, key, mode, padding, iv, blockSize: 8);

        await context.EncryptAsync(inPath, encPath);
        await context.DecryptAsync(encPath, decPath);

        byte[] original = await File.ReadAllBytesAsync(inPath);
        byte[] decrypted = await File.ReadAllBytesAsync(decPath);

        Assert.Equal(original, decrypted);
        
        byte[] encrypted = await File.ReadAllBytesAsync(encPath);
        Assert.NotEqual(original, encrypted);
    }
    
    [Theory]
    [InlineData("test.txt", EncryptionModes.CBC, PaddingModes.PKCS7)]
    [InlineData("test.jpg", EncryptionModes.CTR, PaddingModes.ISO_10126)]
    [InlineData("test.pdf", EncryptionModes.CFB, PaddingModes.ANSIX_923)]
    public async Task TripleDes_FileProcessing_14byte_key(string fileName, EncryptionModes mode, PaddingModes padding)
    {
        string fileNameOnly = Path.GetFileNameWithoutExtension(fileName); 
        string extension = Path.GetExtension(fileName);                  
        string inPath = Path.GetFullPath(Path.Combine(_baseDir, "../../../TestFiles/", fileName));
        string encPath = Path.Combine(_baseDir, "../../../TripleDES/results/encrypted/", $"{fileNameOnly}_encrypted{extension}");
        string decPath = Path.Combine(_baseDir, "../../../TripleDES/results/decrypted/", $"{fileNameOnly}_decrypted{extension}");

        if (!File.Exists(inPath)) return; 

        byte[] key = Encoding.UTF8.GetBytes("tripledtripled"); 
        byte[] iv = Encoding.UTF8.GetBytes("iv_8byte"); 

        var tdes = new cryptography.ciphers.TripleDES.TripleDES();
        var context = new SymmetricContext(tdes, key, mode, padding, iv, blockSize: 8);

        await context.EncryptAsync(inPath, encPath);
        await context.DecryptAsync(encPath, decPath);

        byte[] original = await File.ReadAllBytesAsync(inPath);
        byte[] decrypted = await File.ReadAllBytesAsync(decPath);

        Assert.Equal(original, decrypted);
        
        byte[] encrypted = await File.ReadAllBytesAsync(encPath);
        Assert.NotEqual(original, encrypted);
    }
}