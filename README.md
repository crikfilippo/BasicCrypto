# BasicCrypto

A simple php class to encrypt/decrypt strings with HMAC authentication.

## Setup (once only)

Setup needs to be called **only once** in your application. Minimum requirement is the `saltedKey`:

```php
$saltedKey = $_ENV['CRYPTO_SALTED_KEY']; // Store in environment variable

BasicCrypto::setParams($saltedKey);
```

Other parameters have defaults and are optional:
- `cipherAlgo`: 'AES-256-CBC' (default)
- `initializationVectorLength`: 16 (default)
- `hashAlgo`: 'sha256' (default)

## Generate salted key (first time setup)

Generate all necessary parameters once and store the `saltedKey` in your environment:

```php
$authKey = BasicCrypto::genAuthKey();
$salt = BasicCrypto::genSalt();
$saltedKey = BasicCrypto::genSaltedKey(authKey: $authKey, salt: $salt);

// Store $saltedKey in your .env or secure configuration
// CRYPTO_SALTED_KEY={$saltedKey}
```

## Usage

### Encrypt string:

```php
$encrypted = BasicCrypto::encrypt('hello world');
echo $encrypted;
```

### Decrypt string:

```php
$decrypted = BasicCrypto::decrypt($encrypted);
echo $decrypted; // hello world
```

### Utility methods:

```php
// Get IV length for cipher algorithm
$ivLength = BasicCrypto::getInitializationVectorLength('AES-256-CBC');
```

## Features

- AES-256-CBC encryption
- HMAC authentication (SHA-256)
- Tamper detection
- Random IV for each encryption
- Base64 encoding for safe string handling

## Security

⚠️ **Important**: Store your `saltedKey` in environment variables or secure configuration. Never hardcode it in your source code.
