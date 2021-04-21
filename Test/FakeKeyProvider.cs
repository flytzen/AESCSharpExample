using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.Metadata.Ecma335;
using System.Security.Cryptography;
using System.Xml.Schema;
using Encryptor;

namespace Test
{

    public class FakeKeyProvider : IKeyProvider
    {
        private static readonly Random random = new Random(); // Random is not cryptographicall safe, but should be fine for this

        // "byte" is just a number with a value from 0 to 255.
        private static Dictionary<byte, byte[]> encryptionKeyList = new Dictionary<byte, byte[]>
        {
            { 1,  System.Text.Encoding.ASCII.GetBytes("mysmallkey1234551298765134567890") },
            { 2,  System.Text.Encoding.ASCII.GetBytes("qdfaDFASDFDasdjklDF8798789&ADFQD") },
            { 3,  System.Text.Encoding.ASCII.GetBytes("DFDFSFD78787ASDF890S8FSADFklsajv") },
            { 8,  System.Text.Encoding.ASCII.GetBytes("ASFADF897234234HKJLasfv878sd&dfg") },
            { 37, System.Text.Encoding.ASCII.GetBytes("sAFLSJFLKJSDFjklwrgj8f98079!*()d") }
        };

        public byte[] this[byte i] => encryptionKeyList[i];  // Indexer to make it easier to get a key


        public KeyValuePair<byte, byte[]> GetRandomKey()
        {
            // Hacky code to get a random key
            // Very confusing that the dictionary "key" is the number of the key 
            var chosenDictionaryKeyNumber = random.Next(0, encryptionKeyList.Keys.Count);
            var encryptionKeyNumber = encryptionKeyList.Keys.ToList()[chosenDictionaryKeyNumber];
            var encryptionKey = encryptionKeyList[encryptionKeyNumber];

            return new KeyValuePair<byte, byte[]>(encryptionKeyNumber, encryptionKey);
        }
    }
}