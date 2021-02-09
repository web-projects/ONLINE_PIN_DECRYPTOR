namespace OnlinePinDecryptor.Helpers
{
    public class OnlinePinPayload
    {
        public string KSN { get; set; }
        public string PAN { get; set;  }
        public string EncryptedData { get; set; }
        public string DecryptedData { get; set; }
    }
}
