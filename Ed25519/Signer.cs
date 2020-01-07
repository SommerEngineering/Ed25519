using System;
using System.Collections.Generic;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Encrypter;

namespace Ed25519
{
    public static class Signer
    {
        /// <summary>
        /// Generates a random private key.
        /// </summary>
        /// <param name="password">An optional password to encrypt the key.</param>
        /// <returns>The private key.</returns>
        public static ReadOnlySpan<byte> GeneratePrivateKey(string password = "")
        {
            var privateKey = new Span<byte>(new byte[32]);
            RandomNumberGenerator.Create().GetBytes(privateKey);

            if (!string.IsNullOrWhiteSpace(password))
            {
                using var inputStream = new MemoryStream(privateKey.ToArray(), false);
                using var outputStream = new MemoryStream();

                CryptoProcessor.Encrypt(inputStream, outputStream, password).Wait();
                privateKey = new Span<byte>(outputStream.ToArray());
            }

            return privateKey;
        }

        /// <summary>
        /// Loads a key (public or private key) from a file.
        /// </summary>
        /// <param name="filename">The entire path to the corresponding file.</param>
        /// <returns>The desired key.</returns>
        public static ReadOnlySpan<byte> LoadKey(string filename) => !File.Exists(filename) ? ReadOnlySpan<byte>.Empty : File.ReadAllBytes(filename);

        /// <summary>
        /// Signs a message with the given private and public keys.
        /// </summary>
        /// <param name="message">The message to sign.</param>
        /// <param name="privateKey">The desired private key.</param>
        /// <param name="publicKey">The corresponding public key.</param>
        /// <returns>The derived signature. It's length is always 64 bytes!</returns>
        public static ReadOnlySpan<byte> Sign(ReadOnlySpan<byte> message, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey)
        {
            if(privateKey.Length != Constants.BIT_LENGTH / 8)
                throw new ArgumentException($"Private key length is wrong. Got {privateKey.Length} instead of {Constants.BIT_LENGTH / 8}.");

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
                rSub.Write(privateKeyHash[(Constants.BIT_LENGTH / 8)..]);
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
                nOut.Flush();

                return nOut.ToArray();
            }
        }

        /// <summary>
        /// Validates a given signature by means of the given public key.
        /// </summary>
        /// <param name="signature">The signature to validate.</param>
        /// <param name="message">The corresponding message.</param>
        /// <param name="publicKey">The used public key.</param>
        /// <returns>Returns true when the combination of signature + message is valid.</returns>
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
