using System;
using System.Collections.Generic;
using System.Linq;

namespace OnlinePinDecryptor.TLV
{
    public class TLV
    {
        public byte[] Tag { get; set; }
        public byte[] Data { get; set; }     // Value should be null if innerTags is populated

        public List<TLV> InnerTags { get; set; } // Value should be null if data is populated

        public List<TLV> Decode(byte[] data, int startoffset = 0, int datalength = -1, List<byte[]> tagoftagslist = null)
        {
            if (data == null)
            {
                return null;
            }

            var alltags = new List<TLV>();
            var dataoffset = startoffset;

            if (datalength == -1)
            {
                datalength = data.Length;
            }

            if (tagoftagslist == null)
            {
                tagoftagslist = new List<byte[]>();
            }

            while (dataoffset < datalength)
            {
                var tagStartOffset = dataoffset;
                var tagByte0 = data[dataoffset];
                var tagLength = 1;

                if ((tagByte0 & 0x1F) == 0x1F)
                {
                    // Long form tag
                    dataoffset++;       // Skip first tag byte

                    while ((data[dataoffset] & 0x80) == 0x80)
                    {
                        tagLength++;   // More bit set, so add middle byte to tagLength
                        dataoffset++;
                    }

                    tagLength++;       // Include final byte (where more=0)
                    dataoffset++;
                }
                else if (tagByte0 == 0x80)
                {
                    return alltags;
                }
                else
                {
                    // Short form (single byte) tag
                    dataoffset++;       // Simply increment past single byte tag; tagLength is already 1
                }

                // protect from buffer overrun
                if(dataoffset >= data.Length)
                {
                    return null;
                }

                var lengthByte0 = data[dataoffset];
                var tagDataLength = 0;

                if ((lengthByte0 & 0x80) == 0x80)
                {
                    // Long form length
                    var tagDataLengthLength = lengthByte0 & 0x7F;
                    var tagDataLengthIndex = 0;
                    while (tagDataLengthIndex < tagDataLengthLength)
                    {
                        tagDataLength <<= 8;
                        tagDataLength += data[dataoffset + tagDataLengthIndex + 1];

                        tagDataLengthIndex++;
                    }

                    dataoffset += 1 + tagDataLengthLength;  // Skip long form byte, plus all length bytes
                }
                else
                {
                    // Short form (single byte) length
                    tagDataLength = lengthByte0;
                    dataoffset++;
                }

                var tag = new TLV
                {
                    Tag = new byte[tagLength]
                };

                Array.Copy(data, tagStartOffset, tag.Tag, 0, tagLength);

                var foundTagOfTags = false;
                foreach (var tagOftags in tagoftagslist)
                {
                    if (tagOftags.SequenceEqual(tag.Tag))
                    {
                        foundTagOfTags = true;
                    }
                }

                if (foundTagOfTags)
                {
                    if (dataoffset + tagDataLength > data.Length)
                    {
                        tagDataLength = data.Length - dataoffset;
                    }

                    tag.InnerTags = Decode(data, dataoffset, dataoffset + tagDataLength, tagoftagslist);
                }
                else
                {
                    // special handling of POS cancellation: "ABORTED" is in the data field without a length
                    if (tagDataLength > data.Length)
                    {
                        tagDataLength = data.Length - dataoffset;
                    }
                    tag.Data = new byte[tagDataLength];
                    Array.Copy(data, dataoffset, tag.Data, 0, tagDataLength);
                }

                alltags.Add(tag);

                dataoffset += tagDataLength;
            }

            return /*(allTags.Count == 0) ? null :*/ alltags;
        }

        public byte[] Encode(List<TLV> tags)
        {
            var allTagBytes = new List<byte[]>();
            var allTagBytesLength = 0;

            foreach (var tag in tags)
            {
                var len = tag.Tag.Length;
                var data = tag.Data;

                if (tag.InnerTags != null)
                {
                    data = Encode(tag.InnerTags);
                }

                if (data == null)
                {
                    data = Array.Empty<byte>();
                }

                if (data.Length > 65535)
                {
                    throw new Exception($"TLV data too long for Encode: length {data.Length}");
                }

                if (data.Length > 255)
                {
                    len += 3 + data.Length;
                }
                else if (data.Length > 127)
                {
                    len += 2 + data.Length;
                }
                else
                {
                    len += 1 + data.Length;
                }

                var tagData = new byte[len];
                var tagDataOffset = 0;

                Array.Copy(tag.Tag, 0, tagData, tagDataOffset, tag.Tag.Length);
                tagDataOffset += tag.Tag.Length;

                if (data.Length > 255)
                {
                    tagData[tagDataOffset + 0] = 0x80 + 2;

                    tagData[tagDataOffset + 1] = (byte)(data.Length / 256);

                    tagData[tagDataOffset + 2] = (byte)(data.Length % 256);

                    tagDataOffset += 3;
                }
                else if (data.Length > 127)
                {
                    tagData[tagDataOffset + 0] = 0x80 + 1;

                    tagData[tagDataOffset + 1] = (byte)data.Length;

                    tagDataOffset += 2;
                }
                else
                {
                    tagData[tagDataOffset] = (byte)data.Length;
                    tagDataOffset += 1;
                }

                Array.Copy(data, 0, tagData, tagDataOffset, data.Length);
                tagDataOffset += data.Length;

                allTagBytes.Add(tagData);
                allTagBytesLength += tagDataOffset;
            }

            var allBytes = new byte[allTagBytesLength];
            var allBytesOffset = 0;

            foreach (var tagBytes in allTagBytes)
            {
                Array.Copy(tagBytes, 0, allBytes, allBytesOffset, tagBytes.Length);
                allBytesOffset += tagBytes.Length;
            }

            return allBytes;
        }
    }
}
