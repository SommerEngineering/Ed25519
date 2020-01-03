using System;
using System.Collections.Generic;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Ed25519
{
    public static class Extensions
    {
        internal static ReadOnlySpan<byte> ComputeHash(this ReadOnlySpan<byte> data)
        {
            using var sha512 = SHA512.Create();
            return sha512.ComputeHash(data.ToArray());
        }

        internal static ReadOnlySpan<byte> ComputeHash(this Stream inputStream)
        {
            using var sha512 = SHA512.Create();
            return sha512.ComputeHash(inputStream);
        }

        internal static BigInteger Mod(this BigInteger number, BigInteger modulo)
        {
            var result = number % modulo;
            return result < 0 ? result + modulo : result;
        }

        internal static BigInteger Inv(this BigInteger number)
        {
            return number.ExpMod(2, Constants.Q);
        }

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
            if (exponent.Equals(BigInteger.Zero))
            {
                return BigInteger.One;
            }

            var result = BigInteger.Pow(number.ExpMod(exponent / Constants.TWO, modulo), 2).Mod(modulo);
            
            if (exponent.IsEven)
                return result;

            result *= number;
            result = result.Mod(modulo);
            return result;
        }

        internal static Span<byte> EncodeInt(this BigInteger number)
        {
            var nin = number.ToByteArray();
            var nout = new byte[Math.Max(nin.Length, 32)];
            
            Array.Copy(nin, nout, nin.Length);
            return nout;
        }

        internal static BigInteger DecodeInt(this ReadOnlySpan<byte> data)
        {
            return new BigInteger(data) & Constants.U_N;
        }

        internal static BigInteger HashInt(this MemoryStream data)
        {
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

        internal static int GetBit(this ReadOnlySpan<byte> data, int index)
        {
            return data[index / 8] >> (index % 8) & 1;
        }

        public static ReadOnlySpan<byte> ExtractPublicKey(this ReadOnlySpan<byte> privateKey)
        {
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

        public static ReadOnlySpan<byte> ExtractPublicKey(this Span<byte> privateKey)
        {
            return new ReadOnlySpan<byte>(privateKey.ToArray()).ExtractPublicKey();
        }
    }
}
