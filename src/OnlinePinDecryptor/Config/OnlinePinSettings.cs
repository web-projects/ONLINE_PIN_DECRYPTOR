using System;
using System.Collections.Generic;

namespace OnlinePinDecryptor.Config
{
    [Serializable]
    public class OnlinePinSettings
    {
        public List<string> OnlinePinGroup { get; internal set; } = new List<string>();
    }
}
