using System;
using System.Collections.Generic;
using System.Numerics;
using System.Text;
using Ed25519;
using NUnit.Framework;

namespace Ed25519_Tests
{
    public sealed class EdPointTests
    {
        [Test]
        public void TestScalMul01()
        {
            var point = new EdPoint
            {
                X = new BigInteger(1_000_000_000_000d),
                Y = new BigInteger(1_024),
            };

            var scalar = new BigInteger(10_000);
            var result = point.ScalarMul(scalar);

            Assert.That(result.X, Is.EqualTo(BigInteger.Parse("21818314728053983532520901163316227408567979942776402561242051297393768362536")));
            Assert.That(result.Y, Is.EqualTo(BigInteger.Parse("22622610217554165211892652042645278972766880794387244645923515142420844725944")));
        }

        [Test]
        public void TestExpMod01()
        {
            var number = new BigInteger(10_000d);
            var exponent = new BigInteger(10d);
            var modulo = new BigInteger(105d);

            var result = number.ExpMod(exponent, modulo);
            Assert.That(result, Is.EqualTo(new BigInteger(25d)));
        }
    }
}
