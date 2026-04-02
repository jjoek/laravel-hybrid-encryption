<?php

namespace Jjoek\HybridEncryption\Exceptions;

use Exception;

class EncryptionConfigException extends Exception
{
    public function __construct(string $message = 'Encryption configuration error', int $code = 0, ?\Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
