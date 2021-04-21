A simple example of using AES in C# to encrypt strings with a rotating set of symmetric keys.

It is better to use a unique symmetric key for each string you encrypt and then encrypt that with a public/private key. But sometimes this is not practical.
This example does not use Authenticated Encryption so the encrypted data could be modified randomly.