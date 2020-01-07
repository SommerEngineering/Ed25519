using System;
using System.Collections.Generic;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Encrypter;

namespace Ed25519
{
    public static class Extensions
    {
        internal static ReadOnlySpan<byte> ComputeHash(this ReadOnlySpan<byte> data)
        {
            using var sha512 = SHA512.Create();
            return sha512.ComputeHash(data.ToArray());
        }

        internal static async Task<byte[]> ComputeHashAsync(this byte[] data)
        {
            return await Task.Run(() =>
            {
                using var sha512 = SHA512.Create();
                return sha512.ComputeHash(data);
            });
        }

        internal static ReadOnlySpan<byte> ComputeHash(this Stream inputStream)
        {
            if(inputStream.CanSeek)
                inputStream.Seek(0, SeekOrigin.Begin);

            using var sha512 = SHA512.Create();
            return sha512.ComputeHash(inputStream);
        }

        internal static async Task<byte[]> ComputeHashAsync(this Stream inputStream)
        {
            return await Task.Run(() =>
            {
                if(inputStream.CanSeek)
                    inputStream.Seek(0, SeekOrigin.Begin);

                using var sha512 = SHA512.Create();
                return sha512.ComputeHash(inputStream);
            });
        }

        internal static BigInteger Mod(this BigInteger number, BigInteger modulo)
        {
            var result = number % modulo;
            result = result < 0 ? result + modulo : result;
            return result;
        }

        internal static BigInteger Inv(this BigInteger number) => number.ExpMod(Constants.QM2, Constants.Q);

        internal static BigInteger RecoverX(this BigInteger y)
        {
            var y2 = y * y;
            var xx = (y2 - 1) * (Constants.D * y2 + 1).Inv();
            var x = xx.ExpMod(Constants.RECOVER_X_EXP, Constants.Q);

            if (!(x * x - xx).Mod(Constants.Q).Equals(BigInteger.Zero))
            {
                x = (x * Constants.I).Mod(Constants.Q);
            }

            if (!x.IsEven)
            {
                x = Constants.Q - x;
            }

            return x;
        }

        internal static BigInteger ExpMod(this BigInteger number, BigInteger exponent, BigInteger modulo)
        {
            var numberOperations = (int)Math.Ceiling(BigInteger.Log(exponent, 2)) + 1;
            var series = new bool[numberOperations];
            var previousNumber = exponent;
            for (var n = 0; n < numberOperations; n++)
            {
                if (n == 0)
                {
                    series[n] = !exponent.IsEven;
                    continue;
                }

                var next = previousNumber / Constants.TWO;
                series[n] = !next.IsEven;
                previousNumber = next;
            }

            var result = BigInteger.One;
            for (var n = numberOperations - 2; n >= 0; n--)
            {
                result = BigInteger.Pow(result, 2).Mod(modulo);
                if (series[n])
                {
                    result *= number;
                    result = result.Mod(modulo);
                }
            }

            return result;
        }

        internal static Span<byte> EncodeInt(this BigInteger number)
        {
            var nin = number.ToByteArray();
            var nout = new byte[Math.Max(nin.Length, 32)];
            
            Array.Copy(nin, nout, nin.Length);
            return nout;
        }

        internal static BigInteger DecodeInt(this ReadOnlySpan<byte> data) => new BigInteger(data) & Constants.U_N;

        internal static BigInteger DecodeInt(this byte[] data) => new BigInteger(data) & Constants.U_N;

        internal static BigInteger HashInt(this MemoryStream data)
        {
            data.Seek(0, SeekOrigin.Begin);

            var hash = data.ComputeHash();
            var hashSum = BigInteger.Zero;

            for (var i = 0; i < 2 * Constants.BIT_LENGTH; i++)
            {
                var bit = hash.GetBit(i);
                if (bit != 0)
                {
                    hashSum += Constants.TWO_POW_CACHE[i];
                }
            }

            return hashSum;
        }

        internal static async Task<BigInteger> HashIntAsync(this MemoryStream data)
        {
            data.Seek(0, SeekOrigin.Begin);

            var hash = await data.ComputeHashAsync();
            var hashSum = BigInteger.Zero;

            for (var i = 0; i < 2 * Constants.BIT_LENGTH; i++)
            {
                var bit = hash.GetBit(i);
                if (bit != 0)
                {
                    hashSum += Constants.TWO_POW_CACHE[i];
                }
            }

            return hashSum;
        }

        internal static int GetBit(this ReadOnlySpan<byte> data, int index) => data[index / 8] >> (index % 8) & 1;

        internal static int GetBit(this byte[] data, int index) => data[index / 8] >> (index % 8) & 1;

        /// <summary>
        /// Extracts the public key out of the given private key. The private key must be valid, i.e. must consist of 32 bytes.
        /// </summary>
        /// <param name="privateKey">The private key.</param>
        /// <returns>The corresponding public key. Returns an empty ReadOnlySpan, when the private key's length is incorrect.</returns>
        public static ReadOnlySpan<byte> ExtractPublicKey(this ReadOnlySpan<byte> privateKey)
        {
            if(privateKey.Length != 32)
                return ReadOnlySpan<byte>.Empty;

            var hash = privateKey.ComputeHash();
            var a = Constants.TWO_POW_BIT_LENGTH_MINUS_TWO;
            for (var i = 3; i < Constants.BIT_LENGTH - 2; i++)
            {
                var bit = hash.GetBit(i);
                if (bit != 0)
                {
                    a += Constants.TWO_POW_CACHE[i];
                }
            }

            var bigA = Constants.B.ScalarMul(a);
            return bigA.EncodePoint();
        }

        /// <summary>
        /// Extracts the public key out of the given private key. The private key must be valid, i.e. must consist of 32 bytes.
        /// </summary>
        /// <param name="privateKey">The private key.</param>
        /// <returns>The corresponding public key.</returns>
        public static ReadOnlySpan<byte> ExtractPublicKey(this Span<byte> privateKey) => new ReadOnlySpan<byte>(privateKey.ToArray()).ExtractPublicKey();

        /// <summary>
        /// Extracts the public key out of the given private key. The private key must be valid, i.e. must consist of 32 bytes.
        /// </summary>
        /// <param name="privateKey">The private key.</param>
        /// <returns>The corresponding public key. Returns null, when the private key's length is incorrect.</returns>
        public static async Task<byte[]> ExtractPublicKeyAsync(this byte[] privateKey)
        {
            if (privateKey.Length != 32)
                return null;

            var hash = await privateKey.ComputeHashAsync();
            var a = Constants.TWO_POW_BIT_LENGTH_MINUS_TWO;
            for (var i = 3; i < Constants.BIT_LENGTH - 2; i++)
            {
                var bit = hash.GetBit(i);
                if (bit != 0)
                {
                    a += Constants.TWO_POW_CACHE[i];
                }
            }

            var bigA = Constants.B.ScalarMul(a);
            return bigA.EncodePoint().ToArray();
        }

        /// <summary>
        /// Writes a given key to a file.
        /// </summary>
        /// <param name="key">The chosen key</param>
        /// <param name="filename">The desired file</param>
        public static void WriteKey(this ReadOnlySpan<byte> key, string filename) => File.WriteAllBytes(filename, key.ToArray());

        /// <summary>
        /// Writes a given key to a file.
        /// </summary>
        /// <param name="key">The chosen key</param>
        /// <param name="filename">The desired file</param>
        public static async Task WriteKeyAsync(this byte[] key, string filename) => await File.WriteAllBytesAsync(filename, key);

        /// <summary>
        /// Decrypts an encrypted private key.
        /// </summary>
        /// <param name="privateKey">The encrypted private key.</param>
        /// <param name="password">The matching password.</param>
        /// <returns>The decrypted private key.</returns>
        public static ReadOnlySpan<byte> DecryptPrivateKey(this ReadOnlySpan<byte> privateKey, string password)
        {
            using var inputStream = new MemoryStream(privateKey.ToArray());
            using var outputStream = new MemoryStream();
            CryptoProcessor.Decrypt(inputStream, outputStream, password).Wait();

            return outputStream.ToArray();
        }

        /// <summary>
        /// Decrypts an encrypted private key.
        /// </summary>
        /// <param name="privateKey">The encrypted private key.</param>
        /// <param name="password">The matching password.</param>
        /// <returns>The decrypted private key.</returns>
        public static async Task<byte[]> DecryptPrivateKeyAsync(this byte[] privateKey, string password)
        {
            await using var inputStream = new MemoryStream(privateKey);
            await using var outputStream = new MemoryStream();
            await CryptoProcessor.Decrypt(inputStream, outputStream, password);

            return outputStream.ToArray();
        }
    }
}
