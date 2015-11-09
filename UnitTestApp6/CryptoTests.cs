using System;
using Foundation;
using NUnit.Framework;
using PCLCrypto;
using Security;
using Validation;

namespace UnitTestApp6
{
    [TestFixture]
    public class CryptoTests
    {
        [Test]
        public void KeyEncryption()
        {
            const int keySize = 512;
            string keyIdentifier = Guid.NewGuid().ToString();
            string publicKeyIdentifier = GetPublicKeyIdentifierWithTag(keyIdentifier);
            string privateKeyIdentifier = GetPrivateKeyIdentifierWithTag(keyIdentifier);

            // Configure parameters for the joint keypair.
            var keyPairAttr = new NSMutableDictionary();
            keyPairAttr[KSec.AttrKeyType] = KSec.AttrKeyTypeRSA;
            keyPairAttr[KSec.AttrKeySizeInBits] = NSNumber.FromInt32(keySize);

            // Configure parameters for the private key
            var privateKeyAttr = new NSMutableDictionary();
            privateKeyAttr[KSec.AttrIsPermanent] = NSNumber.FromBoolean(true);
            privateKeyAttr[KSec.AttrApplicationTag] = NSData.FromString(privateKeyIdentifier, NSStringEncoding.UTF8);

            // Configure parameters for the public key
            var publicKeyAttr = new NSMutableDictionary();
            publicKeyAttr[KSec.AttrIsPermanent] = NSNumber.FromBoolean(true);
            publicKeyAttr[KSec.AttrApplicationTag] = NSData.FromString(publicKeyIdentifier, NSStringEncoding.UTF8);

            // Parent the individual key parameters to the keypair one.
            keyPairAttr[KSec.PublicKeyAttrs] = publicKeyAttr;
            keyPairAttr[KSec.PrivateKeyAttrs] = privateKeyAttr;

            // Generate the RSA key.
            SecKey publicKey, privateKey;
            SecStatusCode code = SecKey.GenerateKeyPair(keyPairAttr, out publicKey, out privateKey);
            Verify.Operation(code == SecStatusCode.Success, "status was " + code);

            byte[] plainText = new byte[0]; // when this buffer is non-empty, Encrypt works!
            byte[] cipherText;
            code = publicKey.Encrypt(SecPadding.OAEP, plainText, out cipherText);
            Verify.Operation(code == SecStatusCode.Success, "status was " + code);
        }

        internal static string GetPrivateKeyIdentifierWithTag(string tag)
        {
            return tag + ".privateKey";
        }

        internal static string GetPublicKeyIdentifierWithTag(string tag)
        {
            return tag + ".publicKey";
        }
    }
}