using System;
using System.Collections.Generic;
using System.Text;
using Ed25519;
using NUnit.Framework;
using NUnit.Framework.Constraints;

namespace Ed25519_Tests
{
    public sealed class SignerTests
    {
        [Test]
        public void TestSigner01()
        {
            var message = Encoding.UTF8.GetBytes("This is a test message.");
            var publicKey = Encoding.ASCII.GetBytes("01365464163464646464164641634160"); // 32 bytes
            var privateKey = Encoding.ASCII.GetBytes("Secret key");

            var signature = Signer.Sign(message, privateKey, publicKey);

            Assert.That(signature.Length, Is.EqualTo(64));
        }

        [Test]
        public void TestSigner02()
        {
            var message = Encoding.UTF8.GetBytes("This is a test message.");
            var publicKey = Encoding.ASCII.GetBytes("0136546416346464646416464163416"); // 31 bytes
            var privateKey = Encoding.ASCII.GetBytes("Secret key");

            Assert.That(() => Signer.Sign(message, privateKey, publicKey), Throws.ArgumentException); // Public key is too short
        }

        [Test]
        public void TestSigner03()
        {
            var message = Encoding.UTF8.GetBytes("This is a test message.");
            var publicKey = Encoding.ASCII.GetBytes("01365464163464646464164641634160"); // 32 bytes
            var privateKey = Encoding.ASCII.GetBytes("Secret key");

            var signature = Signer.Sign(message, privateKey, publicKey);
            var validationResult = Signer.Validate(signature, message, publicKey);

            Assert.That(validationResult, Is.True);
        }
    }
}
