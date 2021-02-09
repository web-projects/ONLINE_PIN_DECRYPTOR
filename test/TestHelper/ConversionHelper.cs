using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace TestHelper
{
    public static class ConversionHelper
    {
        /// <summary>
        /// Convert "0123DEF01234" (hex string) to binary data: 0x01 0x23 0xDE 0xF0 0x12 0x34
        ///
        /// </summary>
        /// <param name="valueInHexadecimalFormat"></param>
        /// <returns>returns byte array</returns>
        public static byte[] HexToByteArray(String valueInHexadecimalFormat)
        {
            int NumberChars = valueInHexadecimalFormat.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(valueInHexadecimalFormat.Substring(i, 2), 16);
            return bytes;
        }

        /// <summary>
        /// Expects string in Ascii format
        /// </summary>
        /// <param name="valueInAsciiFormat"></param>
        /// <returns>returns byte array</returns>
        public static byte[] AsciiToByte(string valueInAsciiFormat)
        {
            return UnicodeEncoding.ASCII.GetBytes(valueInAsciiFormat);
        }

        /// <summary>
        /// Expects byte array and converts it to Hexadecimal formatted string
        /// </summary>
        /// <param name="value"></param>
        /// <returns>returns Hexadecimal formatted string</returns>
        public static string ByteArrayToHexString(byte[] value)
        {
            return BitConverter.ToString(value).Replace("-", "");
        }

        /// <summary>
        /// Expects byte array and converts it to Ascii formatted string
        /// </summary>
        /// <param name="value"></param>
        /// <returns>returns ascii formatted string</returns>
        public static string ByteArrayToAsciiString(byte[] value)
        {
            return UnicodeEncoding.ASCII.GetString(value);
        }

        /// <summary>
        /// Expects the first array to equal or smaller than the second array
        /// </summary>
        /// <param name="array1"></param>
        /// <param name="array2"></param>
        /// <returns></returns>
        public static byte[] XORArrays(byte[] array1, byte[] array2)
        {
            byte[] result = new byte[array1.Length];
            for (int i = 0; i < array1.Length; i++)
            {
                result[i] = (byte)(array1[i] ^ array2[i]);
            }
            return result;
        }

        /// <summary>
        /// Splits a string into sized chunks
        /// </summary>
        /// <param name="text"></param>
        /// <param name="length"></param>
        /// <returns></returns>
        public static IEnumerable<string> EnumerateByLength(this string text, int length)
        {
            int index = 0;
            while (index < text.Length)
            {
                int charCount = Math.Min(length, text.Length - index);
                yield return text.Substring(index, charCount);
                index += length;
            }
        }

        /// <summary>
        /// Splits a string into sized chunks
        /// </summary>
        /// <param name="text"></param>
        /// <param name="length"></param>
        /// <returns></returns>
        public static IEnumerable<string> SplitByLength(this string text, int length)
        {
            return text.EnumerateByLength(length).ToArray();
        }
    }
}
