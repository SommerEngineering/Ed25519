using System;
using System.Collections.Generic;
using System.IO;
using System.Numerics;
using System.Text;

namespace Ed25519
{
    public static class Signer
    {
        public static ReadOnlySpan<byte> Sign(ReadOnlySpan<byte> message, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey)
        {
            if(privateKey.Length == 0)
                throw new ArgumentException("Private key length is wrong. Key must not be empty.");

            if (publicKey.Length != Constants.BIT_LENGTH / 8)
                throw new ArgumentException($"Public key length is wrong. Got {publicKey.Length} instead of {Constants.BIT_LENGTH / 8}.");

            var privateKeyHash = privateKey.ComputeHash();
            var privateKeyBits = Constants.TWO_POW_BIT_LENGTH_MINUS_TWO;
            for (var i = 3; i < Constants.BIT_LENGTH - 2; i++)
            {
                var bit = privateKeyHash.GetBit(i);
                if (bit != 0)
                {
                    privateKeyBits += Constants.TWO_POW_CACHE[i];
                }
            }

            BigInteger r;
            using (var rSub = new MemoryStream((Constants.BIT_LENGTH / 8) + message.Length))
            {
                rSub.Write(privateKeyHash[(privateKeyHash.Length/2)..]);
                rSub.Write(message);
                rSub.Flush();

                r = rSub.HashInt();
            }

            var bigR = Constants.B.ScalarMul(r);

            BigInteger s;
            var encodedBigR = bigR.EncodePoint();
            using (var sTemp = new MemoryStream(encodedBigR.Length + publicKey.Length + message.Length))
            {
                sTemp.Write(encodedBigR);
                sTemp.Write(publicKey);
                sTemp.Write(message);
                sTemp.Flush();

                s = (r + sTemp.HashInt() * privateKeyBits).Mod(Constants.L);
            }

            using (var nOut = new MemoryStream(64))
            {
                nOut.Write(encodedBigR);
                nOut.Write(s.EncodeInt());
                return nOut.ToArray();
            }
        }

        public static bool Validate(ReadOnlySpan<byte> signature, ReadOnlySpan<byte> message, ReadOnlySpan<byte> publicKey)
        {
            if (signature.Length != Constants.BIT_LENGTH / 4)
                throw new ArgumentException($"Signature length is wrong. Got {signature.Length} instead of {Constants.BIT_LENGTH / 4}.");

            if (publicKey.Length != Constants.BIT_LENGTH / 8)
                throw new ArgumentException($"Public key length is wrong. Got {publicKey.Length} instead of {Constants.BIT_LENGTH / 8}.");

            var signatureSliceLeft = signature[..(Constants.BIT_LENGTH / 8)];
            var pointSignatureLeft = EdPoint.DecodePoint(signatureSliceLeft);
            var pointPublicKey = EdPoint.DecodePoint(publicKey);

            var signatureSliceRight = signature[(Constants.BIT_LENGTH / 8)..];
            var signatureRight = signatureSliceRight.DecodeInt();
            var encodedSignatureLeftPoint = pointSignatureLeft.EncodePoint();

            BigInteger h;
            using (var sTemp = new MemoryStream(encodedSignatureLeftPoint.Length + publicKey.Length + message.Length))
            {
                sTemp.Write(encodedSignatureLeftPoint);
                sTemp.Write(publicKey);
                sTemp.Write(message);
                sTemp.Flush();

                h = sTemp.HashInt();
            }

            var ra = Constants.B.ScalarMul(signatureRight);
            var ah = pointPublicKey.ScalarMul(h);
            var rb = pointSignatureLeft.Edwards(ah);

            return ra.X.Equals(rb.X) && ra.Y.Equals(rb.Y);
        }
    }
}
