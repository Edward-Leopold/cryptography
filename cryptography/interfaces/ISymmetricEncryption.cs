namespace cryptography.interfaces;

public interface ISymmetricEncryption
{ 
    // void SetRoundKeys(in byte[][] roundKeys); //IReadOnlyList<IReadOnlyList<byte>>(???)
    // redundunt method
    byte[] Encrypt(byte[] inputBlock);
    byte[] Decrypt(byte[] inputBlock);
}   