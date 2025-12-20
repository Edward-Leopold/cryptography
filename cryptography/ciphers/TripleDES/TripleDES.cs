using cryptography.ciphers;
using cryptography.interfaces;

namespace cryptography.ciphers.TripleDES;

public class TripleDES : ISymmetricEncryption
{
    private readonly DES.DES _des1 = new();
    private readonly DES.DES _des2 = new();
    private readonly DES.DES _des3 = new();

    public void SetKey(byte[] key)
    {
        if (key == null) throw new ArgumentNullException(nameof(key));

        byte[] k1 = new byte[8], k2 = new byte[8], k3 = new byte[8];

        if (key.Length == 16)
        {
            Buffer.BlockCopy(key, 0, k1, 0, 8);
            Buffer.BlockCopy(key, 8, k2, 0, 8);
            Buffer.BlockCopy(key, 0, k3, 0, 8);
        }
        else if (key.Length == 14)
        {
            Buffer.BlockCopy(key, 0, k1, 0, 7);
            Buffer.BlockCopy(key, 7, k2, 0, 7);
            Buffer.BlockCopy(key, 0, k3, 0, 7);
        }
        else if (key.Length == 24)
        {
            Buffer.BlockCopy(key, 0, k1, 0, 8);
            Buffer.BlockCopy(key, 8, k2, 0, 8);
            Buffer.BlockCopy(key, 16, k3, 0, 8);
        }
        else if (key.Length == 21)
        {
            Buffer.BlockCopy(key, 0, k1, 0, 7);
            Buffer.BlockCopy(key, 7, k2, 0, 7);
            Buffer.BlockCopy(key, 14, k3, 0, 7);
        }
        else throw new ArgumentException("Key must be 14 or 16 or 21 or 24 bytes.");

        _des1.SetKey(k1);
        _des2.SetKey(k2);
        _des3.SetKey(k3);
    }

    public byte[] Encrypt(byte[] data)
    {
        var res1 = _des1.Encrypt(data);
        var res2 = _des2.Decrypt(res1);
        return _des3.Encrypt(res2);
    }

    public byte[] Decrypt(byte[] data)
    {
        var res1 = _des3.Decrypt(data);
        var res2 = _des2.Encrypt(res1);
        return _des1.Decrypt(res2);
    }
}