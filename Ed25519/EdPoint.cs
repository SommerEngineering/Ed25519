using System;
using System.Collections.Generic;
using System.Numerics;
using System.Text;

namespace Ed25519
{
    internal struct EdPoint
    {
        public BigInteger X { get; set; }

        public BigInteger Y { get; set; }

        public static EdPoint DecodePoint(ReadOnlySpan<byte> pointBytes)
        {
            var y = new BigInteger(pointBytes) & Constants.U_N;
            var x = y.RecoverX();

            if ((x.IsEven ? 0 : 1) != pointBytes.GetBit(Constants.BIT_LENGTH - 1))
            {
                x = Constants.Q - x;
            }

            var point = new EdPoint
            {
                X = x,
                Y = y,
            };

            if (!point.IsOnCurve())
                throw new ArgumentException("Decoding point is not on curve");

            return point;
        }

        public ReadOnlySpan<byte> EncodePoint()
        {
            var nout = this.Y.EncodeInt();
            nout[^1] |= this.X.IsEven ? (byte)0x00 : (byte)0x80;
            return nout;
        }

        public EdPoint Edwards(EdPoint point2)
        {
            var xx12 = this.X * point2.X;
            var yy12 = this.Y * point2.Y;
            var dTemp = Constants.D * xx12 * yy12;

            var x3 = (this.X * point2.Y + point2.X * this.Y) * (1 + dTemp).Inv();
            var y3 = (this.Y * point2.Y + xx12) * (1 - dTemp).Inv();

            return new EdPoint
            {
                X = x3.Mod(Constants.Q),
                Y = y3.Mod(Constants.Q),
            };
        }

        public readonly EdPoint ScalarMul(BigInteger e)
        {
            var numberOperations = (int) Math.Ceiling(BigInteger.Log(e, 2)) + 1;
            var series = new bool[numberOperations];
            var previousNumber = e;
            for (var n = 0; n < numberOperations; n++)
            {
                if (n == 0)
                {
                    series[n] = !e.IsEven;
                    continue;
                }

                var number = previousNumber / Constants.TWO;
                series[n] = !number.IsEven;
                previousNumber = number;
            }

            var result = new EdPoint
            {
                X = BigInteger.Zero,
                Y = BigInteger.One,
            };

            for (var n = numberOperations - 2; n >= 0; n--)
            {
                result = result.EdwardsSquare();
                if (series[n])
                    result = result.Edwards(this);
            }

            return result;
        }

        public EdPoint EdwardsSquare()
        {
            var xx = this.X * this.X;
            var yy = this.Y * this.Y;
            var dTemp = Constants.D * xx * yy;

            var x3 = 2 * this.X * this.Y * (1 + dTemp).Inv();
            var y3 = (yy + xx) * (1 - dTemp).Inv();

            return new EdPoint
            {
                X = x3.Mod(Constants.Q),
                Y = y3.Mod(Constants.Q),
            };
        }

        public bool IsOnCurve()
        {
            var xx = this.X * this.X;
            var yy = this.Y * this.Y;
            var dxxyy = Constants.D * yy * xx;

            return (yy - xx - dxxyy - 1).Mod(Constants.Q).Equals(BigInteger.Zero);
        }
    }
}
