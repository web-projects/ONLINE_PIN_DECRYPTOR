using OnlinePinDecryptor.Helpers;
using System;

namespace OnlinePinDecryptor.Decryptor
{
    public interface IPinDecryptor : IDisposable
    {
        byte[] DecryptData(string initialKSN, string cipher);
        OnlinePinData RetrievePinData(byte[] trackInformation);
    }
}
