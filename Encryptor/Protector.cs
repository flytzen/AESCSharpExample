using System;
using System.Diagnostics.CodeAnalysis;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Encryptor
{
    
    public class Protector 
    {
        const int keyNumberPosition = 0;
        const int ivStartPosition = 1;
        const int encryptedContentStartPosition = 17;

        private readonly IKeyProvider keyProvider;

        public Protector(IKeyProvider keyProvider)
        {
            this.keyProvider = keyProvider;
        }

        public string Protect(string input)
        {
            var inputAsBytes = System.Text.Encoding.UTF8.GetBytes(input);
            var encryptedAsBytes = this.Protect(inputAsBytes);
            return Convert.ToBase64String(encryptedAsBytes);
        }

        public string Unprotect(string encrypted)
        {
            var encryptedBytes = Convert.FromBase64String(encrypted);
            var decryptedBytes = this.Unprotect(encryptedBytes);
            return System.Text.Encoding.UTF8.GetString(decryptedBytes);
        }

        private ReadOnlySpan<byte> Protect(byte[] input)
        {
            var outputLength = CalculateOutputLength(input.Length);
            var output = new byte[outputLength];

            var keyToUse = this.keyProvider.GetRandomKey();
            output[keyNumberPosition] = keyToUse.Key; // Put the number of the key in position 0

            using (var aes = Aes.Create())
            {
                aes.Key = keyToUse.Value;
                aes.IV.CopyTo(output, ivStartPosition); // Put the IV in positions 1 - 16
                var encryptor = aes.CreateEncryptor();
                
                var inputLength = input.Length;
                var initialBlocks = (inputLength - 1) / 16;

                for (int i = 0; i < initialBlocks; i++)
                {
                    var inputPos = i * 16;
                    var outputPos = inputPos + encryptedContentStartPosition;
                    encryptor.TransformBlock(input, inputPos, 16, output, outputPos);
                }

                var finalBlockStart = initialBlocks * 16;
                var finalBlockLength = inputLength - (initialBlocks * 16);
                var finalBlock = encryptor.TransformFinalBlock(input, finalBlockStart, finalBlockLength);
                finalBlock.CopyTo(output, finalBlockStart + encryptedContentStartPosition);
            }

            return output;
        }

        public ReadOnlySpan<byte> Unprotect(byte[] encryptedData)
        {
            var keyNumber = encryptedData[keyNumberPosition];
            var keyToUse = this.keyProvider[keyNumber];
            var iv = encryptedData.AsSpan().Slice(ivStartPosition, 16).ToArray();

            using (var aes = Aes.Create())
            {
                var decryptor = aes.CreateDecryptor(keyToUse, iv);
                return decryptor.TransformFinalBlock(encryptedData, encryptedContentStartPosition, encryptedData.Length - 1 - 16);
            }
        }

        private static int CalculateOutputLength(int inputLength)
        {
            var encryptedContentLength = ((inputLength / 16) + 1) * 16;
            return 1 + 16 + encryptedContentLength;
        }
    }
}
