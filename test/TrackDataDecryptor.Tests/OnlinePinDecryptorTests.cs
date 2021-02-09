using OnlinePinDecryptor.Decryptor;
using OnlinePinDecryptor.Helpers;
using System.Collections.Generic;
using TestHelper;
using Xunit;
using ConversionHelper = TestHelper.ConversionHelper;

namespace OnlinePinDecryptor.Tests
{
    public class OnlinePinDecryptorTests
    {
        readonly PinDecryptor subject;

        public OnlinePinDecryptorTests()
        {
            subject = new PinDecryptor();
        }

        [Theory]
        [InlineData("FFFF9876543211000620", 3)]
        [InlineData("FFFF9876543211000636", 6)]
        [InlineData("FFFF9876543211000637", 7)]
        public void GetTotalEncryptionPasses_ShouldReturnNumberOfPasses_WhenCalled(string ksn, int expectedValue)
        {
            byte[] initialKSN = ConversionHelper.HexToByteArray(ksn);

            Helper.CallPrivateMethod("GetTotalEncryptionPasses", subject, out List<int> passList, new object[] { initialKSN });

            Assert.Equal(expectedValue, passList.Count);
        }

        [Theory]
        [InlineData("F876543210040B800009", "6799998900000074316", "B2449FABB96D4228", "04439CFFFFFF8BCE")]
        [InlineData("F876543210040B800008", "6799998900000070199", "4BB4136EEA406C2A", "04439CFFFFFF8FE6")]
        public void DecryptPinData_ShouldDecryptPinData_WhenCalled(string ksn, string pan, string encryptedPinData, string decryptedPinData)
        {
            byte[] expectedValue = ConversionHelper.HexToByteArray(decryptedPinData);

            byte[] actualValue = subject.DecryptData(ksn, encryptedPinData);

            Assert.Equal(expectedValue, actualValue);

            // Decode PIN Block: format ISO-0

        }
    }
}