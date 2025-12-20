using cryptography.interfaces;
using cryptography.feistel;
using cryptography.ciphers.DEAL.components;

namespace cryptography.ciphers.DEAL;

public class DEAL : ISymmetricEncryption
{
    private readonly FeistelNetwork _network;
    private byte[]? _key;

    public DEAL()
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
        if (data.Length != 16) throw new ArgumentException("DEAL block size must be 16 bytes.");
        
        return _network.Encrypt(data, _key);
    }

    public byte[] Decrypt(byte[] data)
    {
        if (_key == null) throw new InvalidOperationException("Key not set");
        if (data.Length != 16) throw new ArgumentException("DEAL block size must be 16 bytes.");

        return _network.Decrypt(data, _key);
    }
}