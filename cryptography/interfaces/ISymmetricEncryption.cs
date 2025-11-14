namespace cryptography.interfaces;

public interface ISymmetricEncryption
{ 
    // void SetRoundKeys(in byte[][] roundKeys); //IReadOnlyList<IReadOnlyList<byte>>(???)
    // byte[] Encrypt(in byte[] inputBlock)
    // byte[] Decrypt(in byte[] inputBlock)
    // redundunt method
    
    // byte[] Encrypt(in byte[] inputBlock, in byte[] key);
    // byte[] Decrypt(in byte[] inputBlock, in byte[] key);
    
    void SetKey(byte[] key);
    byte[] Encrypt(byte[] inputBlock);
    byte[] Decrypt(byte[] inputBlock);
}   