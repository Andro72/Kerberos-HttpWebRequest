using System;
using System.Collections.Generic;
using System.Linq;

namespace KerberosAuth
{
    public static class AsnDer
    {
        public static byte[] Encode(byte[] identifier, byte[]data)
        {
            byte[] len;

            int lengthNeed = BitConverter.GetBytes(data.Length).Where(z => z != 0x00).ToArray().Length;


            if (lengthNeed == 1)        //shot form
            {
                len = BitConverter.GetBytes(data.Length).Where(z => z != 0x00).ToArray();
            }
            else                        //long form
            {
                len = new byte[1];
                len[0] = (byte) (0x80 + lengthNeed);
                var lenData = BitConverter.GetBytes(data.Length).Where(z => z != 0x00).Reverse().ToArray();
                len = len.Concat(lenData).ToArray();
            }
            
            
            return identifier.Concat(len).Concat(data).ToArray();
        }


        public static int Decode(byte[] inData, List<byte> identifier, List<byte> data)
        {
            identifier.Add(inData[0]);

            int startIndexOfData = 0;
            int tokenDataLength = 0;
            int tokenAllLength = 0;

            // First check if the extended length bit is set
            if (IsBitSet(inData[1], 7))
            {
                //long version
                byte lenOfLen =(byte) (inData[1] - 0x80);
                startIndexOfData = 2+lenOfLen;
                byte[] lenData = inData.ToList().GetRange(2, lenOfLen).ToArray();
                tokenDataLength = BitConverter.ToInt16(lenData.Reverse().ToArray(), 0);

                tokenAllLength = tokenDataLength + startIndexOfData;
            }
            else
            {
                //short version
                startIndexOfData = 2;
                tokenDataLength = (int)inData[1];
                tokenAllLength = tokenDataLength + startIndexOfData;
            }

            byte[] dataByte = new byte[tokenDataLength];
            Array.Copy(inData,startIndexOfData,dataByte,0, tokenDataLength);
            data.AddRange(dataByte.ToList());

            return tokenAllLength;
        }
        

        public static bool IsBitSet(byte b, int pos)
        {
            return (b & (1 << pos)) != 0;
        }
    }
}
