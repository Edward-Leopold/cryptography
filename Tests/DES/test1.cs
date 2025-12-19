using System.Text;
using cryptography.ciphers.DES;
using cryptography.ciphers.DES.components;
using cryptography.SymmetricContext;
using Xunit.Abstractions;

namespace Tests.DES;


public class DesSymmetricTests
{
    private readonly ITestOutputHelper _output;
    public DesSymmetricTests(ITestOutputHelper output)
    {
        _output = output;
    }
    
    [Fact]
    public async Task Des_StandardVector_ZeroKey_ZeroData_ShouldMatch()
    {
        byte[] key = new byte[8]; 
        byte[] data = new byte[8];
        
        var des = new cryptography.ciphers.DES.DES();
        
        var context = new SymmetricContext(
            des, 
            key, 
            EncryptionModes.ECB, 
            PaddingModes.PKCS7
        );

        byte[] encrypted = await context.EncryptAsync(data);
        byte[] decrypted = await context.DecryptAsync(encrypted);

        Assert.Equal(data, decrypted);
        Assert.Single(new[] { decrypted.Length }, 8); 
    }

    [Fact]
    public async Task Des_FullCycle_StringMessage_ShouldWork()
    {
        byte[] key = Encoding.UTF8.GetBytes("key12345");
        byte[] data = Encoding.UTF8.GetBytes("SecretMessage"); 
        
        var des = new cryptography.ciphers.DES.DES();
        var context = new SymmetricContext(des, key, EncryptionModes.ECB, PaddingModes.PKCS7);
        
        byte[] encrypted = await context.EncryptAsync(data);
        byte[] decrypted = await context.DecryptAsync(encrypted);

        Assert.Equal(data, decrypted);
        Assert.Equal("SecretMessage", Encoding.UTF8.GetString(decrypted));
    }
    
    [Fact]
    public async Task Des_FullCycle_StringMessage()
    {
        byte[] key = Encoding.UTF8.GetBytes("ключ"); // 8 байт
        byte[] data = Encoding.UTF8.GetBytes("SecretMessage"); // 13 байт (не кратно 8)
        
        var des = new cryptography.ciphers.DES.DES();
        var context = new SymmetricContext(des, key, EncryptionModes.ECB, PaddingModes.PKCS7);

        byte[] encrypted = await context.EncryptAsync(data);
        byte[] decrypted = await context.DecryptAsync(encrypted);
        
        _output.WriteLine($"Исходные данные: {Encoding.UTF8.GetString(data)}");
        _output.WriteLine($"Зашифрованные байты: {BitConverter.ToString(encrypted)}");
        _output.WriteLine($"Расшифрованный текст: {Encoding.UTF8.GetString(decrypted)}");
        
        Assert.Equal(data, decrypted);
        Assert.Equal("SecretMessage", Encoding.UTF8.GetString(decrypted));
    }
    
    [Fact]
    public async Task Des_Img_Test()
    {
        string baseDir = AppContext.BaseDirectory;
        string inPath = Path.Combine(baseDir, "../../../TestFiles/test.jpg"); 
        string outPathEnc = Path.Combine(baseDir, "../../../DES/results/encrypted/test_encrypted.jpg");
        string outPathDec = Path.Combine(baseDir, "../../../DES/results/decrypted/test_decrypted.jpg");

        if (!File.Exists(inPath)) 
            throw new FileNotFoundException("Исходный файл не найден по пути: " + Path.GetFullPath(inPath));

        byte[] key = Encoding.UTF8.GetBytes("key12345"); 
        var des = new cryptography.ciphers.DES.DES();
        var context = new SymmetricContext(des, key, EncryptionModes.PCBC, PaddingModes.PKCS7);

        await context.EncryptAsync(inPath, outPathEnc);
        
        _output.WriteLine(Path.GetFullPath(inPath) + "  out: " + Path.GetFullPath(outPathEnc));
        await context.DecryptAsync(outPathEnc, outPathDec);

        byte[] originalBytes = await File.ReadAllBytesAsync(inPath);
        byte[] decryptedBytes = await File.ReadAllBytesAsync(outPathDec);

        Assert.Equal(originalBytes.Length, decryptedBytes.Length);
        Assert.Equal(originalBytes, decryptedBytes);

        byte[] encryptedBytes = await File.ReadAllBytesAsync(outPathEnc);
        Assert.NotEqual(originalBytes, encryptedBytes);
        
    }
    
    [Fact]
    public async Task Des_Pdf_Test()
    {
        string baseDir = AppContext.BaseDirectory;
        string inPath = Path.Combine(baseDir, "../../../TestFiles/test.pdf"); 
        string outPathEnc = Path.Combine(baseDir, "../../../DES/results/encrypted/test_encrypted.bin");
        string outPathDec = Path.Combine(baseDir, "../../../DES/results/decrypted/test_decrypted.pdf");

        if (!File.Exists(inPath)) 
            throw new FileNotFoundException("Исходный файл не найден по пути: " + Path.GetFullPath(inPath));

        byte[] key = Encoding.UTF8.GetBytes("key12345"); 
        var des = new cryptography.ciphers.DES.DES();
        var context = new SymmetricContext(des, key, EncryptionModes.RandomDelta, PaddingModes.ISO_10126);

        await context.EncryptAsync(inPath, outPathEnc);
        
        _output.WriteLine(Path.GetFullPath(inPath) + "  out: " + Path.GetFullPath(outPathEnc));
        await context.DecryptAsync(outPathEnc, outPathDec);

        byte[] originalBytes = await File.ReadAllBytesAsync(inPath);
        byte[] decryptedBytes = await File.ReadAllBytesAsync(outPathDec);

        Assert.Equal(originalBytes.Length, decryptedBytes.Length);
        Assert.Equal(originalBytes, decryptedBytes);

        byte[] encryptedBytes = await File.ReadAllBytesAsync(outPathEnc);
        Assert.NotEqual(originalBytes, encryptedBytes);
        
    }
    
    [Fact]
    public async Task Des_Txt_Test()
    {
        string baseDir = AppContext.BaseDirectory;
        string inPath = Path.Combine(baseDir, "../../../TestFiles/test.txt"); 
        string outPathEnc = Path.Combine(baseDir, "../../../DES/results/encrypted/test_encrypted.txt");
        string outPathDec = Path.Combine(baseDir, "../../../DES/results/decrypted/test_decrypted.txt");

        if (!File.Exists(inPath)) 
            throw new FileNotFoundException("Исходный файл не найден по пути: " + Path.GetFullPath(inPath));

        byte[] key = Encoding.UTF8.GetBytes("key12345"); 
        var des = new cryptography.ciphers.DES.DES();
        var context = new SymmetricContext(des, key, EncryptionModes.CFB, PaddingModes.Zeros);

        await context.EncryptAsync(inPath, outPathEnc);
        
        _output.WriteLine(Path.GetFullPath(inPath) + "  out: " + Path.GetFullPath(outPathEnc));
        await context.DecryptAsync(outPathEnc, outPathDec);

        byte[] originalBytes = await File.ReadAllBytesAsync(inPath);
        byte[] decryptedBytes = await File.ReadAllBytesAsync(outPathDec);

        Assert.Equal(originalBytes.Length, decryptedBytes.Length);
        Assert.Equal(originalBytes, decryptedBytes);

        byte[] encryptedBytes = await File.ReadAllBytesAsync(outPathEnc);
        Assert.NotEqual(originalBytes, encryptedBytes);
        
    }
}