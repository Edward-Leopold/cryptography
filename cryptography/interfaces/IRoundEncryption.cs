namespace cryptography.interfaces;

public interface IRoundEncryption
{
    byte[] EncryptRoundConversion(byte[] inputBlock, byte[] roundKey);
}