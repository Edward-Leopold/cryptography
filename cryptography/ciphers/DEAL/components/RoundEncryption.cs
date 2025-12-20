using cryptography.interfaces;
using cryptography.ciphers.DES;

namespace cryptography.ciphers.DEAL.components;

public class RoundEncryption : IRoundEncryption
{
    private readonly DES.DES _des;

    public RoundEncryption()
    {
        _des = new DES.DES();
    }

    public byte[] EncryptRoundConversion(byte[] inputBlock, byte[] roundKey)
    {
        _des.SetKey(roundKey);
        return _des.Encrypt(inputBlock);
    }
}