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
        
        // Используем твой контекст. 
        // ВАЖНО: PKCS7 добавит второй блок набивки, так как 8 байт кратны размеру блока.
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
        byte[] key = Encoding.UTF8.GetBytes("key12345"); // 8 байт
        byte[] data = Encoding.UTF8.GetBytes("SecretMessage"); // 13 байт (не кратно 8)
        
        var des = new cryptography.ciphers.DES.DES();
        var context = new SymmetricContext(des, key, EncryptionModes.ECB, PaddingModes.PKCS7);

        // Act
        byte[] encrypted = await context.EncryptAsync(data);
        byte[] decrypted = await context.DecryptAsync(encrypted);

        // Assert
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

        // Act
        byte[] encrypted = await context.EncryptAsync(data);
        byte[] decrypted = await context.DecryptAsync(encrypted);
        
        _output.WriteLine($"Исходные данные: {Encoding.UTF8.GetString(data)}");
        _output.WriteLine($"Зашифрованные байты: {BitConverter.ToString(encrypted)}");
        _output.WriteLine($"Расшифрованный текст: {Encoding.UTF8.GetString(decrypted)}");
        
        // Assert
        Assert.Equal(data, decrypted);
        Assert.Equal("SecretMessage", Encoding.UTF8.GetString(decrypted));
    }
    
    [Fact]
    public void Permutations_IP_Then_IPINV_ShouldBeIdentity()
    {
        byte[] data = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
    
        // Применяем начальную перестановку
        var ip = cryptography.Utilities.Permutations.PermutateByTable(
            data, cryptography.ciphers.DES.constants.DesConstants.IP, 
            cryptography.Utilities.Permutations.BitsIndexingMode.HighToLow, 1);
        
        // Применяем инверсную перестановку
        var ipInv = cryptography.Utilities.Permutations.PermutateByTable(
            ip, cryptography.ciphers.DES.constants.DesConstants.IP_INV, 
            cryptography.Utilities.Permutations.BitsIndexingMode.HighToLow, 1);

        Assert.Equal(data, ipInv);
    }
}