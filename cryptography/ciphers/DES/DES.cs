using cryptography.Utilities;
using cryptography.ciphers.DES.constants;
using cryptography.feistel;
using cryptography.ciphers.DES.components;
using cryptography.interfaces;

namespace cryptography.ciphers.DES;

public class DES : ISymmetricEncryption
{
    private readonly FeistelNetwork _network;
    private byte[]? _key;
    public DES()
    {
        _network = new FeistelNetwork(new KeysGenerator(), new RoundEncryption());
    }
    
    public void SetKey(byte[] key)
    {
        _key = key ?? throw new ArgumentNullException(nameof(key));
    }
    public byte[] Encrypt(byte[] data)    
    {
        if (_key == null) throw new InvalidOperationException("Key not set");
        var permuted = Permutations.PermutateByTable(data, DesConstants.IP, Permutations.BitsIndexingMode.HighToLow, 1);
        var encrypted = _network.Encrypt(permuted, _key);
        var inversionPermuted = Permutations.PermutateByTable(encrypted, DesConstants.IP_INV, Permutations.BitsIndexingMode.HighToLow, 1);
        return inversionPermuted;
    }
    
    public byte[] Decrypt(byte[] data)
    {
        if (_key == null) throw new InvalidOperationException("Key not set");
        var permuted = Permutations.PermutateByTable(data, DesConstants.IP, Permutations.BitsIndexingMode.HighToLow, 1);
        var decrypted = _network.Decrypt(permuted, _key);
        var inversionPermuted =
            Permutations.PermutateByTable(decrypted, DesConstants.IP_INV, Permutations.BitsIndexingMode.HighToLow, 1);
        return inversionPermuted;
    }
}