using System;
using System.Linq;
using Encryptor;
using Shouldly;
using Xunit;

namespace Test
{
    public class ProtectionTests
    {
        [Theory]
        [InlineData("")]
        [InlineData("0123456789abcd")]
        [InlineData("0123456789abcde")]
        [InlineData("0123456789abcdef")]
        [InlineData("0123456789abcdefg")]
        [InlineData("0123456789abcdefgh")]
        public void CanProtect(string input)
        {
            var protector = new Protector(new FakeKeyProvider());
            var encrypted = protector.Protect(input);

            var unprotector = new Protector(new FakeKeyProvider());
            var decrypted = unprotector.Unprotect(encrypted);

            encrypted.ShouldNotBe(input);
            encrypted.Length.ShouldBeGreaterThan(input.Length);

            decrypted.ShouldBe(input);
        }
    }
}
