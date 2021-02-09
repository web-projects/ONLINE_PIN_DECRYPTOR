using Microsoft.Extensions.Configuration;
using OnlinePinDecryptor.Decryptor;
using OnlinePinDecryptor.Helpers;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;

namespace OnlinePinDecryptor
{
    /// <summary>
    /// 
    /// Program to validate Online Pin decryptor
    ///
    /// BDK: 0123456789ABCDEFFEDCBA9876543210
    /// KEY LEN: 32 BYTES
    /// 
    /// DFDF10: ENCRYPTED PIN
    /// dfdf10-50-87a73106f57b8fbdd383a257ed8c713a62bfae83e9b0d202c50fe1f7da8739338c768ba61506c1d3404191c7c8c3016929a0cce6621b95191d5a006382605fb0c17963725b548abc37ffda146e0429e7
    /// KEY LEN: 80 bytes
    /// 
    /// DFDF11: KSN
    /// dfdf11-0a-ffff9876543211000620
    /// KEY LEN: 10 bytes
    /// 
    /// DFDF12: IV DATA
    /// dfdf12-08-a79ddd0ff736b32b
    /// KEY LEN: 8 bytes
    /// 
    /// </summary>
    class Program
    {
        // Actual Transactions
        public static List<OnlinePinPayload> trackPayload = new List<OnlinePinPayload>()
        {
            // TEST: FFFF9876543211000620
            new OnlinePinPayload()
            {
                KSN = "FFFF9876543211000620",
                PAN = "6799998900000074316",
                EncryptedData = "",
                DecryptedData = ""
            },
        };

        static void Main(string[] args)
        {
            Console.WriteLine($"\r\n==========================================================================================");
            Console.WriteLine($"{Assembly.GetEntryAssembly().GetName().Name} - Version {Assembly.GetEntryAssembly().GetName().Version}");
            Console.WriteLine($"==========================================================================================\r\n");

            //InternalTesting();
            ConfigurationLoad();
        }

        static void ConfigurationLoad()
        {
            // Get appsettings.json config.
            IConfiguration configuration = new ConfigurationBuilder()
                .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
                .AddEnvironmentVariables()
                .Build();


            var onlinePin = configuration.GetSection("OnlinePinGroup:OnlinePin")
                    .GetChildren()
                    .ToList()
                    .Select(x => new
                    {
                        onlinePinKsn = x.GetValue<string>("KSN"),
                        onlinePinData = x.GetValue<string>("EncryptedData")
                    });

            // set the target index
            int index = 0;

            if (onlinePin.Count() > index)
            {
                string onlinePinKsn = onlinePin.ElementAt(index).onlinePinKsn;
                string onlinePinData = onlinePin.ElementAt(index).onlinePinData;

                try
                {
                    PinDecryptor decryptor = new PinDecryptor();

                    Debug.WriteLine($"KSN      : {onlinePinKsn}");
                    Console.WriteLine($"KSN      : {onlinePinKsn}");
                    Console.WriteLine($"DATA     : {onlinePinData}");

                    // decryptor in action
                    byte[] trackInformation = decryptor.DecryptData(onlinePinKsn, onlinePinData);

                    string decryptedTrack = ConversionHelper.ByteArrayToHexString(trackInformation);

                    //1234567890|1234567890|12345
                    Console.WriteLine($"OUTPUT   : {decryptedTrack}");
                    Debug.WriteLine($"OUTPUT ____: {decryptedTrack}");

                    //MSRTrackData trackInfo = decryptor.RetrieveAdditionalData(trackInformation);
                    OnlinePinData pinInfo = decryptor.RetrievePinData(trackInformation);

                    //1234567890|1234567890|12345
                    Debug.WriteLine($"PAN DATA     : {pinInfo.PANData}");
                }
                catch (Exception e)
                {
                    Console.WriteLine($"EXCEPTION: {e.Message}");
                }
            }
        }

        static void InternalTesting()
        {
            try
            {
                foreach (var item in trackPayload)
                {
                    PinDecryptor decryptor = new PinDecryptor();

                    // decryptor in action
                    byte[] trackInformation = decryptor.DecryptData(item.KSN, item.EncryptedData);

                    string decryptedTrack = ConversionHelper.ByteArrayToHexString(trackInformation);

                    //1234567890|1234567890|12345
                    Debug.WriteLine($"OUTPUT ____: {decryptedTrack}");
                    Console.WriteLine($"OUTPUT : [{decryptedTrack}]");

                    byte[] expectedValue = ConversionHelper.HexToByteArray(item.DecryptedData);
                    bool result = StructuralComparisons.StructuralEqualityComparer.Equals(expectedValue, trackInformation);
                    Console.WriteLine($"EQUAL  : [{result}]");

                    OnlinePinData pinData = decryptor.RetrievePinData(trackInformation);
                    Console.WriteLine($"CHOLDER: [{pinData.PANData}]");
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"EXCEPTION: {e.Message}");
            }
        }
    }
}
