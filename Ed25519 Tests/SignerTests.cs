using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Ed25519;
using NUnit.Framework;

namespace Ed25519_Tests
{
    public sealed class SignerTests
    {
        [Test]
        public void TestSigner01()
        {
            var message = Encoding.UTF8.GetBytes("This is a test message.");
            var privateKey = new Span<byte>(new byte[32]);
            RandomNumberGenerator.Create().GetBytes(privateKey);

            var publicKey = privateKey.ExtractPublicKey();
            var signature = Signer.Sign(message, privateKey, publicKey);

            Assert.That(signature.Length, Is.EqualTo(64));
        }

        [Test]
        public void TestSigner02()
        {
            var message = Encoding.UTF8.GetBytes("This is a test message.");
            var privateKey = new Span<byte>(new byte[32]);
            RandomNumberGenerator.Create().GetBytes(privateKey);

            var publicKey = privateKey.ExtractPublicKey()[2..];

            try
            {
                Signer.Sign(message, privateKey, publicKey);
            }
            catch (ArgumentException e)
            {
                Assert.That(true); // Public key is too short!
            }
        }

        [Test]
        public void TestSigner03()
        {
            var message = Encoding.UTF8.GetBytes("This is a test message.");
            var privateKey = new Span<byte>(new byte[32]);
            RandomNumberGenerator.Create().GetBytes(privateKey);

            var publicKey = privateKey.ExtractPublicKey();
            var signature = Signer.Sign(message, privateKey, publicKey);
            var validationResult = Signer.Validate(signature, message, publicKey);

            Assert.That(validationResult, Is.True);
        }

        [Test]
        public void TestSigner04()
        {
            var messageOriginal = Encoding.UTF8.GetBytes("This is a test message.");
            var privateKey = new Span<byte>(new byte[32]);
            RandomNumberGenerator.Create().GetBytes(privateKey);

            var publicKey = privateKey.ExtractPublicKey();
            var signature = Signer.Sign(messageOriginal, privateKey, publicKey);

            var messageAltered = Encoding.UTF8.GetBytes("This is a test message!");
            var validationResult = Signer.Validate(signature, messageAltered, publicKey);

            Assert.That(validationResult, Is.False); // Message was altered!
        }

        // See https://tools.ietf.org/html/rfc8032#section-7.1
        [Test]
        public void TestRFC8032Test01()
        {
            var message = new ReadOnlySpan<byte>(); // Empty message!
            var publicKey = new byte[]
            {
                0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
                0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
            };
            
            var privateKey = new byte[]
            {
                0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
                0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
            };

            var expectedSignature = new byte[]
            {
                0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
                0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55,
                0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
                0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24, 0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
            };

            var signature = Signer.Sign(message, privateKey, publicKey);
            Assert.That(signature.ToArray(), Is.EqualTo(expectedSignature));

            var validationResult = Signer.Validate(signature, message, publicKey);
            Assert.That(validationResult, Is.True);
        }
    }
}
