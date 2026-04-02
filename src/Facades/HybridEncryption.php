<?php

namespace Jjoek\HybridEncryption\Facades;

use Illuminate\Support\Facades\Facade;
use Jjoek\HybridEncryption\Services\HybridEncryptionService;

/**
 * @method static string getPublicKey()
 * @method static bool isConfigured()
 * @method static array decrypt(array $encryptedPayload)
 *
 * @see \Jjoek\HybridEncryption\Services\HybridEncryptionService
 */
class HybridEncryption extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return HybridEncryptionService::class;
    }
}
