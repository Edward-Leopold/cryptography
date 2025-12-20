using cryptography.interfaces;

namespace cryptography.ciphers.RC4;

public class RC4 : ISymmetricEncryption
{
    private byte[]? _key;
    private byte[] _s = new byte[256];

    public void SetKey(byte[] key)
    {
        if (key == null || key.Length == 0) 
            throw new ArgumentException("Key cannot be empty.");
        _key = key;
    }

    private void InitializeSBox(byte[] key)
    {
        for (int i = 0; i < 256; i++)
            _s[i] = (byte)i;

        int j = 0;
        for (int i = 0; i < 256; i++)
        {
            j = (j + _s[i] + key[i % key.Length]) % 256;
            Swap(i, j);
        }
    }

    private void Swap(int i, int j)
    {
        byte temp = _s[i];
        _s[i] = _s[j];
        _s[j] = temp;
    }

    public byte[] Process(byte[] data)
    {
        if (_key == null) throw new InvalidOperationException("Key not set.");
        
        InitializeSBox(_key); 

        int i = 0;
        int j = 0;
        byte[] result = new byte[data.Length];

        for (int k = 0; k < data.Length; k++)
        {
            i = (i + 1) % 256;
            j = (j + _s[i]) % 256;
            Swap(i, j);

            int t = (_s[i] + _s[j]) % 256;
            byte keystreamByte = _s[t];

            result[k] = (byte)(data[k] ^ keystreamByte);
        }

        return result;
    }
    
    public async Task ProcessFileAsync(string inputPath, string outputPath)
    {
        byte[] inputData = await File.ReadAllBytesAsync(inputPath);
        byte[] outputData = await Task.Run(() => Process(inputData));
        await File.WriteAllBytesAsync(outputPath, outputData);
    }

    public byte[] Encrypt(byte[] data) => Process(data);
    public byte[] Decrypt(byte[] data) => Process(data);
}