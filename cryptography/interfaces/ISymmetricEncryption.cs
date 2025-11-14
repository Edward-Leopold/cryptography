namespace cryptography.interfaces;

public interface ISymmetricEncryption
{ 
    void SetRoundKeys(in byte[][] roundKeys); //IReadOnlyList<IReadOnlyList<byte>>(???)
    byte[] Encrypt(byte[] inputBlock);
    byte[] Decrypt(byte[] inputBlock);
}   