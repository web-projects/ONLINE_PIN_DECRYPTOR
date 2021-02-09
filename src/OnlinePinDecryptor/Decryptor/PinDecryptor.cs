using OnlinePinDecryptor.Helpers;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace OnlinePinDecryptor.Decryptor
{
    /// <summary>
    /// MSR Track Decryptor to allow extraction on the following:
    /// PAN, NAME, ADDITIONAL DATA (EXPIRATION DATE, SERVICE CODE), DISCRETIONARY DATA (PVKI, PVV, CVV, CVC)
    /// </summary>
    public class PinDecryptor : IPinDecryptor
    {
        const int RegisterSize = 16;
        const int CardholderNameSize = 26;
        const int MinimumCipherLength = 96;

        // BASE-DERIVATION KEY
        const string BDK = "0123456789ABCDEFFEDCBA9876543210";
        readonly string BDK24;
        readonly byte[] BDKMASK;

        // Masking elements
        readonly byte[] KSNZERO = new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xE0, 0x00, 0x00 };
        readonly byte[] RGMASK = new byte[] { 0xC0, 0xC0, 0xC0, 0xC0, 0x00, 0x00, 0x00, 0x00, 0xC0, 0xC0, 0xC0, 0xC0, 0x00, 0x00, 0x00, 0x00 };
        readonly byte[] DDMASK = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00 };
        readonly byte[] PNMASK = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF };

        public PinDecryptor()
        {
            BDK24 = BDK + BDK.Substring(0, 16);
            BDKMASK = ConversionHelper.HexToByteArray(BDK);
        }

        public void Dispose()
        {

        }

        /// <summary>
        /// TripleDES encrypt KSN with the 24 byte "0123456789ABCDEFFEDCBA98765432100123456789ABCDEF" BDK.
        /// The result of this encryption should generate the left register of the IPEK.
        /// </summary>
        /// <param name="ksn"></param>
        /// <returns></returns>
        byte[] SetKSNZeroCounter(byte[] ksn)
        {
            byte[] zeroksn = new byte[ksn.Length];
            int i = 0;

            foreach (byte value in ksn)
            {
                zeroksn[i] = (byte)(KSNZERO[i] & value);
                i++;
            }

            // Only need the first 8 bytes of the KSN
            byte[] adjustedksn = new byte[ksn.Length - 2];
            Array.Copy(zeroksn, adjustedksn, adjustedksn.Length);

            return adjustedksn;
        }

        /// <summary>
        /// To setup the right register mask:
        /// BDK xor C0C0C0C000000000C0C0C0C000000000
        ///	0123456789ABCDEFFEDCBA9876543210 xor C0C0C0C000000000C0C0C0C000000000
        ///
        ///	Process right register by appending the most significant 8 bytes (8-MSB) to the resulting 24 byte key
        ///	
        /// </summary>
        /// <returns></returns>
        byte[] SetRightRegisterMask()
        {
            byte[] rrksn = new byte[BDKMASK.Length];
            int i = 0;

            // BDK ^ RGMASK
            foreach (byte value in BDKMASK)
            {
                rrksn[i] = (byte)(RGMASK[i] ^ value);
                i++;
            }

            // Append 8-MSB from the resulting masked array
            byte[] rightRegister = new byte[BDKMASK.Length + 8];
            Array.Copy(rrksn, rightRegister, rrksn.Length);
            Array.Copy(rrksn, 0, rightRegister, rrksn.Length, 8);

            return rightRegister;
        }

        /// <summary>
        /// The least significant 21 bits of the KSN hold a counter representing how many card swipes have occurred on the device
        /// We look for how many 1's are in the binary representation of that counter for our number of encryption passes to execute
        /// </summary>
        /// <param name="ksn"></param>
        /// <returns></returns>
        List<int> GetTotalEncryptionPasses(byte[] ksn)
        {
            int passes = 0;

            List<int> totalShifts = new List<int>();
            byte[] counter = new byte[4];
            Array.Copy(ksn, 6, counter, 0, 4);
            Array.Reverse(counter);
            int counterValue = BitConverter.ToInt32(counter, 0) & 0x001FFFFF;

            int i = 0;
            for (int shiftReg = 0x00100000; shiftReg > 0; shiftReg >>= 1, i++)
            {
                if ((shiftReg & counterValue) > 0)
                {
                    //Debug.WriteLine(string.Format("SHIFT REG _: {0:X4}", shiftReg));
                    totalShifts.Add(shiftReg);
                    passes++;
                }
            }
            //Debug.WriteLine($"TOTAL SHIFT: {i}");
            Debug.WriteLine($"TOTAL PASS : {passes}");

            return totalShifts;
        }

        byte[] GenerateLeftRegister(byte[] ksnZeroCounter)
        {
            using (var tdes = new TripleDESCryptoServiceProvider())
            {
                tdes.Mode = CipherMode.ECB;
                tdes.Padding = PaddingMode.PKCS7;
                tdes.Key = ConversionHelper.HexToByteArray(BDK24);

                using (var transform = tdes.CreateEncryptor())
                {
                    byte[] lrbytes = transform.TransformFinalBlock(ksnZeroCounter, 0, ksnZeroCounter.Length);
                    // Left Register is first 8 bytes
                    byte[] leftRegister = new byte[8];
                    Array.Copy(lrbytes, leftRegister, 8);
                    return leftRegister;
                }
            }
        }

        byte[] GenerateRightRegister(byte[] ksnZeroCounter)
        {
            using (var tdes = new TripleDESCryptoServiceProvider())
            {
                tdes.Mode = CipherMode.ECB;
                tdes.Padding = PaddingMode.PKCS7;
                tdes.Key = SetRightRegisterMask();

                using (var transform = tdes.CreateEncryptor())
                {
                    byte[] rrbytes = transform.TransformFinalBlock(ksnZeroCounter, 0, ksnZeroCounter.Length);
                    // Right Register is first 8 bytes
                    byte[] rightRegister = new byte[8];
                    Array.Copy(rrbytes, rightRegister, 8);
                    return rightRegister;
                }
            }
        }

        byte[] SetDataMask(byte[] key)
        {
            byte[] rgkey = new byte[DDMASK.Length];
            int i = 0;

            // key ^ DDMASK
            foreach (byte value in key)
            {
                rgkey[i] = (byte)(DDMASK[i] ^ value);
                i++;
            }

            // Append 8-MSB from the resulting masked array
            byte[] registerKey = new byte[DDMASK.Length];
            Array.Copy(rgkey, registerKey, rgkey.Length);

            //1234567890|1234567890|12345
            Debug.WriteLine($"DATA-MASKED KEY : {ConversionHelper.ByteArrayToHexString(registerKey)}");

            return registerKey;
        }
        
        byte[] SetPinMask(byte[] key)
        {
            byte[] rgkey = new byte[PNMASK.Length];
            int i = 0;

            // key ^ PPMASK
            foreach (byte value in key)
            {
                rgkey[i] = (byte)(PNMASK[i] ^ value);
                i++;
            }

            // Append 8-MSB from the resulting masked array
            byte[] registerKey = new byte[PNMASK.Length];
            Array.Copy(rgkey, registerKey, rgkey.Length);

            //1234567890|1234567890|12345
            Debug.WriteLine($"PIN-MASKED KEY : {ConversionHelper.ByteArrayToHexString(registerKey)}");

            return registerKey;
        }

        byte[] SetRegisterMask(byte[] key)
        {
            byte[] rgkey = new byte[RGMASK.Length];
            int i = 0;

            // key ^ RGMASK
            foreach (byte value in key)
            {
                rgkey[i] = (byte)(RGMASK[i] ^ value);
                i++;
            }

            // Append 8-MSB from the resulting masked array
            byte[] registerKey = new byte[RGMASK.Length];
            Array.Copy(rgkey, registerKey, rgkey.Length);

            //1234567890|1234567890|12345
            Debug.WriteLine($"MASKED KEY : {ConversionHelper.ByteArrayToHexString(registerKey)}");

            return registerKey;
        }

        byte[] GenerateDataRegister(byte[] key, byte[] ksn)
        {
            // break down key in two parts
            byte[] top8Value = new byte[key.Length / 2];
            byte[] bot8Value = new byte[key.Length / 2];

            Array.Copy(key, 0, top8Value, 0, key.Length / 2);
            Array.Copy(key, key.Length / 2, bot8Value, 0, key.Length / 2);

            byte[] regkey = new byte[key.Length / 2];
            int i = 0;

            // Bottom XOR value
            foreach (byte value in ksn)
            {
                regkey[i] = (byte)(bot8Value[i] ^ value);
                i++;
            }

            //Debug.WriteLine($"TOP-8 _____: {ConversionHelper.ByteArrayToHexString(top8Value)}");
            //Debug.WriteLine($"BOT-8 _____: {ConversionHelper.ByteArrayToHexString(regkey)}");

            // single-DES Encryption
            using (var des = new DESCryptoServiceProvider())
            {
                des.Mode = CipherMode.ECB;
                des.Padding = PaddingMode.None;
                des.Key = top8Value;

                using (var transform = des.CreateEncryptor())
                {
                    byte[] ssbytes = transform.TransformFinalBlock(regkey, 0, regkey.Length);
                    byte[] registerKey = new byte[ssbytes.Length];

                    i = 0;

                    // single-DES using bottom of 8 bytes of key XOR'd with KSN
                    foreach (byte value in ssbytes)
                    {
                        registerKey[i] = (byte)(bot8Value[i] ^ value);
                        i++;
                    }

                    return registerKey;
                }
            }
        }

        byte[] EDE3KeyExpand(byte[] finalKey)
        {
            int expandedKeyLen = finalKey.Length + finalKey.Length / 2;
            byte[] expandedKey = new byte[expandedKeyLen];
            Array.Copy(finalKey, expandedKey, finalKey.Length);
            Array.Copy(finalKey, 0, expandedKey, finalKey.Length, finalKey.Length / 2);
            return expandedKey;
        }

        byte[] SetDataKeyVariantKSN(byte[] ksn, int counterValue)
        {
            byte[] dataSessionKSN = new byte[ksn.Length];

            if (counterValue > 0)
            {
                Array.Copy(ksn, dataSessionKSN, ksn.Length);

                int i = 0;
                for (int shiftReg = 0x00100000; shiftReg > 0; shiftReg >>= 1, i++)
                {
                    if ((shiftReg & counterValue) > 0)
                    {
                        dataSessionKSN[5] |= (byte)((shiftReg >> 16) & 0x0000FF);
                        dataSessionKSN[6] |= (byte)((shiftReg >> 8) & 0x0000FF);
                        dataSessionKSN[7] |= (byte)((shiftReg >> 0) & 0x0000FF);
                    }
                }
            }
            else
            {
                Array.Copy(ksn, 2, dataSessionKSN, 0, ksn.Length - 2);
            }

            return dataSessionKSN;
        }

        byte[] GenerateKey(byte[] key, byte[] ksn)
        {
            // generate register mask
            byte[] maskedKey = SetRegisterMask(key);

            byte[] registerKeys = new byte[RegisterSize];

            // LEFT REGISTER ENCRYPTION
            byte[] leftRegister = GenerateDataRegister(maskedKey, ksn);
            Array.Copy(leftRegister, registerKeys, leftRegister.Length);

            // RIGHT REGISTER ENCRYPTION
            byte[] rightRegister = GenerateDataRegister(key, ksn);
            Array.Copy(rightRegister, 0, registerKeys, rightRegister.Length, rightRegister.Length);

            //1234567890|1234567890|12345
            Debug.WriteLine($"IPEK_______: {ConversionHelper.ByteArrayToHexString(leftRegister)}-{ConversionHelper.ByteArrayToHexString(rightRegister)}");

            return registerKeys;
        }

        byte[] CreateDataSessionKey(byte[] registerKeys, byte[] ksn)
        {
            try
            {
                // generate register mask
                byte[] maskedKey = SetPinMask(registerKeys);

                // left half
                byte[] ede3Key = EDE3KeyExpand(maskedKey);

                //1234567890|1234567890|12345
                Debug.WriteLine($"PEK REDUCED: {ConversionHelper.ByteArrayToHexString(ede3Key)}");

                byte[] sessionKey = new byte[24];
                byte[] dataSessionKSN = SetDataKeyVariantKSN(ksn, 0);

                using (var tdes = new TripleDESCryptoServiceProvider())
                {
                    tdes.Mode = CipherMode.ECB;
                    tdes.Padding = PaddingMode.PKCS7;
                    tdes.Key = ede3Key;

                    // LEFT HALF
                    using (var transform = tdes.CreateEncryptor())
                    {
                        byte[] lHalf = new byte[8];
                        Array.Copy(maskedKey, lHalf, 8);
                        byte[] ssbytes = transform.TransformFinalBlock(lHalf, 0, lHalf.Length);
                        Array.Copy(ssbytes, sessionKey, 8);
                    }

                    // RIGHT HALF
                    using (var transform = tdes.CreateEncryptor())
                    {
                        byte[] rHalf = new byte[8];
                        Array.Copy(maskedKey, 8, rHalf, 0, 8);
                        byte[] ssbytes = transform.TransformFinalBlock(rHalf, 0, rHalf.Length);
                        Array.Copy(ssbytes, 0, sessionKey, 8, 8);

                        //1234567890|1234567890|12345
                        Debug.WriteLine($"CURRENT KEY: {ConversionHelper.ByteArrayToHexString(sessionKey)}");

                        // Add extended bytes to session key
                        Array.Copy(sessionKey, 0, sessionKey, 16, 8);

                        return sessionKey;
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"EXCEPTION: {e.Message}");
                return null;
            }
        }

        byte[] CreatePinSessionKey(byte[] registerKeys, byte[] ksn)
        {
            try
            {
                // generate register mask
                byte[] maskedKey = SetPinMask(registerKeys);

                // left half
                byte[] ede3Key = EDE3KeyExpand(maskedKey);

                //1234567890|1234567890|12345
                Debug.WriteLine($"PEK REDUCED: {ConversionHelper.ByteArrayToHexString(ede3Key)}");

                return ede3Key;
            }
            catch (Exception e)
            {
                Console.WriteLine($"EXCEPTION: {e.Message}");
                return null;
            }
        }

        byte[] GenerateIPEK(byte[] baseKSN)
        {
            byte[] registerKeys = new byte[RegisterSize];

            // LEFT REGISTER ENCRYPTION
            byte[] leftRegister = GenerateLeftRegister(baseKSN);
            Array.Copy(leftRegister, registerKeys, leftRegister.Length);

            // RIGHT REGISTER ENCRYPTION
            byte[] rightRegister = GenerateRightRegister(baseKSN);
            Array.Copy(rightRegister, 0, registerKeys, rightRegister.Length, rightRegister.Length);

            //1234567890|1234567890|12345
            Debug.WriteLine($"IPEK_______: {ConversionHelper.ByteArrayToHexString(leftRegister)}-{ConversionHelper.ByteArrayToHexString(rightRegister)}");

            return registerKeys;
        }

        /// <summary>
        /// Decryption setup requires to iterate through the number of potential swipes that have already occurred with the KSN
        /// being used to decrypt. Once we iterate through all possibilities, we end up with the final decrypting key used to decrypt the data.
        /// </summary>
        /// <param name="ksn"></param>
        /// <param name="cipher"></param>
        /// <returns></returns>
        public byte[] DecryptData(string initialKSN, string cipher)
        {
            byte[] finalBytes = null;

            // Initial KSN
            byte[] ksn = ConversionHelper.HexToByteArray(initialKSN);

            List<int> totalPasses = GetTotalEncryptionPasses(ksn);

            // Base IPEK
            byte[] iPEK = GenerateIPEK(ksn);

            // Set KSN counter to 0
            byte[] ksnZeroCounter = SetKSNZeroCounter(ksn);

            // Set BASE KSN
            byte[] baseKSN = SetDataKeyVariantKSN(ksnZeroCounter, 0);
            Debug.WriteLine($"BASE KSN __: {ConversionHelper.ByteArrayToHexString(baseKSN)}");

            foreach (int pass in totalPasses)
            {
                baseKSN = SetDataKeyVariantKSN(baseKSN, pass);

                //1234567890|1234567890|12345
                Debug.WriteLine($"ACTIVE KSN : {ConversionHelper.ByteArrayToHexString(baseKSN)}");

                iPEK = GenerateKey(iPEK, baseKSN);
            }

            //byte[] sessionKey = CreateDataSessionKey(iPEK, baseKSN);
            byte[] sessionKey = CreatePinSessionKey(iPEK, baseKSN);

            //1234567890|1234567890|12345
            Debug.WriteLine($"DECRYPT KEY: {ConversionHelper.ByteArrayToHexString(sessionKey)}");
            Console.WriteLine($"DECRYPTOR: {ConversionHelper.ByteArrayToHexString(sessionKey)}");

            using (var tdes = new TripleDESCryptoServiceProvider())
            {
                tdes.Mode = CipherMode.CBC;
                tdes.Padding = PaddingMode.None;
                tdes.Key = sessionKey;
                tdes.IV = new byte[8];

                using (var transform = tdes.CreateDecryptor())
                {
                    byte[] textBytes = ConversionHelper.HexToByteArray(cipher);
                    finalBytes = transform.TransformFinalBlock(textBytes, 0, textBytes.Length);
                }
            }

            return finalBytes;
        }

        /*public MSRTrackData RetrieveTrackData(byte[] trackInformation)
        {
            MSRTrackData trackData = new MSRTrackData()
            {
                PANData = string.Empty,
                Name = string.Empty,
                ExpirationDate = string.Empty,
                DiscretionaryData = string.Empty
            };

            // xF�E�t�24180001234563^FDCS TEST CARD /MASTERCARD^25121010001111123456789012?C�
            //string decryptedTrack = ConversionHelper.ByteArrayToUTF8String(trackInformation);
            //string decryptedTrack = ConversionHelper.ByteArrayToAsciiString(trackInformation);

            // xF?E?t?24180001234563^FDCS TEST CARD /MASTERCARD^25121010001111123456789012?C?
            string decryptedTrack = Regex.Replace(ConversionHelper.ByteArrayToAsciiString(trackInformation), @"[^\u0020-\u007E]", string.Empty);

            // expected format: PAN^NAME^ADDITIONAL DATA^DISCRETIONARY DATA
            //MatchCollection match = Regex.Matches(decryptedTrack, "(?:[^^^?]+)", RegexOptions.Compiled);
            MatchCollection match = Regex.Matches(decryptedTrack, "([^^^]+)", RegexOptions.Compiled);

            if (match.Count >= 3)
            {
                // PAN DATA
                MatchCollection pan = Regex.Matches(match[0].Value, "(?:[^^^?]+)", RegexOptions.Compiled);

                if (pan.Count >= 4)
                { 
                    trackData.PANData = Regex.Replace(pan[3].Value, @"[^\u0020-\u007E]", string.Empty);
                }

                // NAME
                trackData.Name = match[1].Value;

                // ADDITIONAL DATA
                MatchCollection track1 = Regex.Matches(match[2].Value, "(?:[^^^?]+)", RegexOptions.Compiled);

                if (track1.Count >= 1)
                {
                    trackData.ExpirationDate = track1[0].Value.Substring(0, 4);
                    trackData.ServiceCode = track1[0].Value.Substring(4, 3);

                    if (track1.Count >= 2)
                    {
                        MatchCollection discretionary = Regex.Matches(track1[1].Value, "^[[:ascii:]]+");
                        if (discretionary.Count > 0)
                        {
                            trackData.DiscretionaryData = discretionary[0].Value;
                        }
                    }
                }
            }

            return trackData;
        }*/

        /// <summary>
        /// The Track 1 structure is specified as:
        ///     STX : Start sentinel "%"
        ///     FC : Format code "B" (The format described here.Format "A" is reserved for proprietary use.)
        ///     PAN : Payment card number 4400664987366029, up to 19 digits
        ///     FS : Separator "^"
        ///     NM : Name, 2 to 26 characters(including separators, where appropriate, between surname, first name etc.)
        ///     FS : Separator "^"
        ///     ED : Expiration data, 4 digits or "^"
        ///     SC : Service code, 3 digits or "^"
        ///     DD : Discretionary data, balance of characters
        ///     ETX : End sentinel "?"
        ///     LRC : Longitudinal redundancy check, calculated according to ISO/IEC 7811-2
        ///     
        /// REGULAR EXPRESSION
        /// ^%B([0-9]{1,19})\^([^\^]{2,26})\^([0-9]{4}|\^)([0-9]{3}|\^)([^\?]+)\?$
        /// 
        /// </summary>
        /// <param name="trackInformation"></param>
        /// <returns></returns>
        public OnlinePinData RetrievePinData(byte[] pinInformation)
        {
            OnlinePinData pinData = new OnlinePinData()
            {
                PANData = string.Empty,
            };

            // clean up track data
            string decryptedPin = Regex.Replace(ConversionHelper.ByteArrayToAsciiString(pinInformation), @"[^\u0020-\u007E]", string.Empty, RegexOptions.Compiled);
            Debug.WriteLine($"DECRYPTED _: {decryptedPin}");

            // expected format: PAN^NAME^ADDITIONAL-DATA^DISCRETIONARY-DATA
            MatchCollection match = Regex.Matches(decryptedPin, @"%B([0-9 ]{1,19})\^([^\^]{2,26})\^([0-9]{4}|\^)([0-9]{3}|\^)([^\?]+)\?", RegexOptions.Compiled);

            // DISCRETIONARY DATA is optional
            if (match.Count == 1 && match[0].Groups.Count >= 5)
            {
                // PAN DATA
                pinData.PANData = match[0].Groups[1].Value;
            }


            return pinData;
        }
    }
}
