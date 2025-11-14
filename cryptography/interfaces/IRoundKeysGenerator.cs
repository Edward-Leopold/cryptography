namespace cryptography.interfaces;

public interface IRoundKeysGenerator
{
    byte[][] GenerateRoundKeys(in byte[] key);
}