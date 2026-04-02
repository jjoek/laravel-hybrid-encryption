<?php

namespace Jjoek\HybridEncryption\Services;

use Jjoek\HybridEncryption\Exceptions\DecryptionException;
use Jjoek\HybridEncryption\Exceptions\EncryptionConfigException;
use phpseclib3\Crypt\RSA;
use phpseclib3\Crypt\PublicKeyLoader;

class HybridEncryptionService
{
    private ?string $privateKey;
    private ?string $publicKey;

    public function __construct()
    {
        $this->privateKey = config('hybrid-encryption.private_key');
        $this->publicKey = config('hybrid-encryption.public_key');
    }

    /**
     * Get the public key for frontend encryption.
     *
     * @throws EncryptionConfigException
     */
    public function getPublicKey(): string
    {
        if (empty($this->publicKey)) {
            throw new EncryptionConfigException('Public key not configured. Set ENCRYPTION_PUBLIC_KEY in your .env file.');
        }

        return $this->publicKey;
    }

    /**
     * Check if encryption is properly configured.
     */
    public function isConfigured(): bool
    {
        return !empty($this->privateKey) && !empty($this->publicKey);
    }

    /**
     * Decrypt an encrypted request payload.
     *
     * @param array{encryptedKey: string, encryptedData: string, iv: string} $encryptedPayload
     * @return array<string, mixed>
     * @throws DecryptionException
     * @throws EncryptionConfigException
     */
    public function decrypt(array $encryptedPayload): array
    {
        $this->validatePayload($encryptedPayload);

        if (empty($this->privateKey)) {
            throw new EncryptionConfigException('Private key not configured. Set ENCRYPTION_PRIVATE_KEY in your .env file.');
        }

        // Decode base64 values
        $encryptedKey = base64_decode($encryptedPayload['encryptedKey'], true);
        $encryptedData = base64_decode($encryptedPayload['encryptedData'], true);
        $iv = base64_decode($encryptedPayload['iv'], true);

        if ($encryptedKey === false || $encryptedData === false || $iv === false) {
            throw new DecryptionException('Invalid base64 encoding in encrypted payload');
        }

        // Validate IV length (should be 12 bytes for AES-GCM)
        if (strlen($iv) !== 12) {
            throw new DecryptionException('Invalid IV length. Expected 12 bytes for AES-GCM.');
        }

        // Decrypt the AES key using RSA-OAEP
        $aesKey = $this->decryptRsaOaep($encryptedKey);

        // Validate AES key length (should be 32 bytes for AES-256)
        if (strlen($aesKey) !== 32) {
            throw new DecryptionException('Invalid AES key length. Expected 32 bytes for AES-256.');
        }

        // Decrypt the data using AES-256-GCM
        $decryptedData = $this->decryptAesGcm($encryptedData, $aesKey, $iv);

        // Parse JSON
        $data = json_decode($decryptedData, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new DecryptionException('Decrypted data is not valid JSON: ' . json_last_error_msg());
        }

        return $data;
    }

    /**
     * Decrypt the AES key using RSA-OAEP with SHA-256.
     *
     * @throws DecryptionException
     */
    private function decryptRsaOaep(string $encryptedKey): string
    {
        try {
            $privateKey = PublicKeyLoader::load($this->privateKey);

            // Configure for RSA-OAEP with SHA-256 (matching Web Crypto API)
            $privateKey = $privateKey
                ->withPadding(RSA::ENCRYPTION_OAEP)
                ->withHash('sha256')
                ->withMGFHash('sha256');

            $decryptedKey = $privateKey->decrypt($encryptedKey);

            if ($decryptedKey === false) {
                throw new DecryptionException('Failed to decrypt AES key with RSA-OAEP');
            }

            return $decryptedKey;
        } catch (\Exception $e) {
            throw new DecryptionException('Failed to decrypt AES key with RSA-OAEP: ' . $e->getMessage());
        }
    }

    /**
     * Decrypt data using AES-256-GCM.
     *
     * @throws DecryptionException
     */
    private function decryptAesGcm(string $encryptedData, string $aesKey, string $iv): string
    {
        // AES-GCM appends the auth tag to the ciphertext
        // The tag is 16 bytes (128 bits) at the end
        $tagLength = 16;

        if (strlen($encryptedData) < $tagLength) {
            throw new DecryptionException('Encrypted data too short to contain authentication tag');
        }

        $ciphertext = substr($encryptedData, 0, -$tagLength);
        $tag = substr($encryptedData, -$tagLength);

        $decrypted = openssl_decrypt(
            $ciphertext,
            'aes-256-gcm',
            $aesKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        if ($decrypted === false) {
            throw new DecryptionException('Failed to decrypt data with AES-256-GCM. Authentication may have failed: ' . openssl_error_string());
        }

        return $decrypted;
    }

    /**
     * Validate the encrypted payload structure.
     *
     * @throws DecryptionException
     */
    private function validatePayload(array $payload): void
    {
        $required = ['encryptedKey', 'encryptedData', 'iv'];

        foreach ($required as $field) {
            if (!isset($payload[$field])) {
                throw new DecryptionException("Missing required field: {$field}");
            }

            if (!is_string($payload[$field])) {
                throw new DecryptionException("Field '{$field}' must be a string");
            }

            if (empty($payload[$field])) {
                throw new DecryptionException("Field '{$field}' cannot be empty");
            }
        }
    }
}
