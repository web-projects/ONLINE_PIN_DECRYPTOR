using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace OnlinePinDecryptor.TLV
{
    public class TLVEncoding
    {
        public enum TLVDataEncoding
        {
            ASCII,
            Binary,
            Decimal
        }

        public byte[] Tag { get; set; } = Array.Empty<byte>();
        public string Name { get; set; } = string.Empty;
        public TLVDataEncoding Encoding { get; set; } = TLVDataEncoding.Binary;
        public bool EMVData { get; set; } = false;

        private static readonly List<TLVEncoding> TLVEncodings = new List<TLVEncoding>
        {
            new TLVEncoding
            {
                Tag = new byte[] { 0x9F, 0x1C },
                Name = "TerminalID",
                Encoding = TLVDataEncoding.ASCII
            },
            new TLVEncoding
            {
                Tag = new byte[] { 0x9F, 0x1E },
                Name = "SerialNumber",
                Encoding = TLVDataEncoding.ASCII
            },
            new TLVEncoding
            {
                Tag = new byte[] { 0xDF, 0xA2, 0x1D },
                Name = "MaximumChainedCommandsSize",
                Encoding = TLVDataEncoding.Decimal
            },
            new TLVEncoding
            {
                Tag = new byte[] { 0xEE },
                Name = "TerminalInfo"
            },
            new TLVEncoding
            {
                Tag = new byte[] { 0xDF, 0x0D },
                Name = "Name",
                Encoding = TLVDataEncoding.ASCII
            },
            new TLVEncoding
            {
                Tag = new byte[] { 0xDF, 0x7F },
                Name = "Version",
                Encoding = TLVDataEncoding.ASCII
            },
            new TLVEncoding
            {
                Tag = new byte[] { 0xEF },
                Name = "VersionInfo"
            },
            new TLVEncoding
            {
                Tag = new byte[] { 0xDF, 0x81, 0x06 },
                Name = "LibraryName",
                Encoding = TLVDataEncoding.ASCII
            },
            new TLVEncoding
            {
                Tag = new byte[] { 0xDF, 0x81, 0x07 },
                Name = "LibraryVersion",
                Encoding = TLVDataEncoding.ASCII
            },
            new TLVEncoding
            {
                Tag = new byte[] { 0xDF, 0x81, 0x08 },
                Name = "Architecture",
                Encoding = TLVDataEncoding.ASCII
            },
            new TLVEncoding
            {
                Tag = new byte[] { 0xDF, 0x81, 0x09 },
                Name = "ArchitectureType",
                Encoding = TLVDataEncoding.ASCII
            },
            new TLVEncoding
            {
                Tag = new byte[] { 0xDF, 0xEC, 0x1F },
                Name = "PowerUpTimeSec",
                Encoding = TLVDataEncoding.Decimal
            },
            new TLVEncoding
            {
                Tag = new byte[] { 0xDF, 0x81, 0x01 },
                Name = "TamperStatus"
            },
            new TLVEncoding
            {
                Tag = new byte[] { 0xDF, 0x81, 0x02 },
                Name = "ARSStatus"
            },
            new TLVEncoding
            {
                Tag = new byte[] { 0xF0 },
                Name = "PinPad"
            },
            new TLVEncoding
            {
                Tag = new byte[] { 0xDF, 0x81, 0x11 },
                Name = "PinPadStatus"
            },
            new TLVEncoding
            {
                Tag = new byte[] { 0xDF, 0x81, 0x0A },
                Name = "ModelNumber",
                Encoding = TLVDataEncoding.ASCII
            },
            new TLVEncoding
            {
                Tag = new byte[] { 0xDF, 0x81, 0x0B },
                Name = "HardwareVersion",
                Encoding = TLVDataEncoding.ASCII
            },
            new TLVEncoding
            {
                Tag = new byte[] { 0xDF, 0x81, 0x0C },
                Name = "PartNumber",
                Encoding = TLVDataEncoding.ASCII
            },
            new TLVEncoding
            {
                Tag = new byte[] { 0xDF, 0x81, 0x0D },
                Name = "OSNumber",
                Encoding = TLVDataEncoding.ASCII
            },
            new TLVEncoding
            {
                Tag = new byte[] { 0xDF, 0x81, 0x0E },
                Name = "AQUILAVersion",
                Encoding = TLVDataEncoding.ASCII
            },
            new TLVEncoding
            {
                Tag = new byte[] { 0xDF, 0x81, 0x0F },
                Name = "IPPMiddlewareVersion",
                Encoding = TLVDataEncoding.ASCII
            },
            new TLVEncoding
            {
                Tag = new byte[] { 0xDF, 0x81, 0x10 },
                Name = "PermanentUnitSerialNumber",
                Encoding = TLVDataEncoding.ASCII
            },
            new TLVEncoding
            {
                Tag = new byte[] { 0xDF, 0xA2, 0x02 },
                Name = "OptionID"
            },
            new TLVEncoding
            {
                Tag = new byte[] { 0xDF, 0xED, 0x14 },
                Name = "VSS Script Filename",
                Encoding = TLVDataEncoding.ASCII
            }
        };

        public void PrintTags(List<TLV> tags, int indent = 0)
        {
            if (tags == null)
            {
                return;
            }

            var indentString = new string('\t', indent);

            foreach (var tag in tags)
            {
                TLVEncoding encoding = new TLVEncoding
                {
                    Name = "Unknown-" + BitConverter.ToString(tag.Tag)
                };

                foreach (var tagEncoding in TLVEncodings)
                {
                    if (tag.Tag.SequenceEqual(tagEncoding.Tag))
                    {
                        encoding = tagEncoding;
                        break;
                    }
                }
                if (tag.InnerTags != null)
                {
#if DEBUG
                    Console.WriteLine($"{indentString}{encoding.Name}:");
#endif
                    PrintTags(tag.InnerTags, indent + 1);
                }
                else
                {
                    var value = BitConverter.ToString(tag.Data);

                    if (encoding.Encoding == TLVDataEncoding.ASCII)
                    {
                        value = System.Text.Encoding.UTF8.GetString(tag.Data);
                    }
                    else if (encoding.Encoding == TLVDataEncoding.Decimal)
                    {
                        Decimal decimalValue = 0;

                        foreach (var byt in tag.Data)
                        {
                            decimalValue *= 256;
                            decimalValue += byt;
                        }

                        value = decimalValue.ToString(CultureInfo.InvariantCulture);
                    }
#if DEBUG
                    Console.WriteLine($"{indentString}{encoding.Name}: {value}");
#endif
                }
            }
        }
    }
}
