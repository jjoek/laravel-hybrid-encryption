<?php

namespace Jjoek\HybridEncryption\Exceptions;

use Exception;

class DecryptionException extends Exception
{
    public function __construct(string $message = 'Decryption failed', int $code = 0, ?\Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
