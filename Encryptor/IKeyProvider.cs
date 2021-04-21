using System.Collections.Generic;

namespace Encryptor
{
    public interface IKeyProvider
    {
        KeyValuePair<byte, byte[]> GetRandomKey();
        byte[] this[byte i] { get; }
    }
}