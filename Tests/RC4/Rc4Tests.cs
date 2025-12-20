using System.Text;
using cryptography.ciphers.RC4;
using Xunit;

namespace Tests.RC4;

public class Rc4Tests
{
    [Fact]
    public async Task Rc4_String_EncryptionDecryption_ShouldWork()
    {
        var rc4 = new cryptography.ciphers.RC4.RC4();
        byte[] key = Encoding.UTF8.GetBytes("very_secret_key");
        byte[] original = Encoding.UTF8.GetBytes("Hello, RC4 world!");

        rc4.SetKey(key);

        byte[] encrypted = rc4.Encrypt(original);
        byte[] decrypted = rc4.Decrypt(encrypted);

        Assert.Equal(original, decrypted);
        Assert.NotEqual(original, encrypted);
    }
    
    [Theory]
    [InlineData("test.txt")]
    [InlineData("test.jpg")]
    [InlineData("test.pdf")]
    public async Task TripleDes_FileProcessing_ShouldPreserveData(string fileName)
    {
        string fileNameOnly = Path.GetFileNameWithoutExtension(fileName); 
        string extension = Path.GetExtension(fileName);               
        string baseDir = AppContext.BaseDirectory;
        string inPath = Path.GetFullPath(Path.Combine(baseDir, "../../../TestFiles/", fileName));
        string encPath = Path.Combine(baseDir, "../../../RC4/results/encrypted/", $"{fileNameOnly}_encrypted{extension}");
        string decPath = Path.Combine(baseDir, "../../../RC4/results/decrypted/", $"{fileNameOnly}_decrypted{extension}");

        if (!File.Exists(inPath)) return; 

        var rc4 = new cryptography.ciphers.RC4.RC4();
        rc4.SetKey(Encoding.UTF8.GetBytes("file_key_123"));

        await rc4.ProcessFileAsync(inPath, encPath);
        await rc4.ProcessFileAsync(encPath, decPath);

        byte[] original = await File.ReadAllBytesAsync(inPath);
        byte[] restored = await File.ReadAllBytesAsync(decPath);

        Assert.Equal(original, restored);
    }
}