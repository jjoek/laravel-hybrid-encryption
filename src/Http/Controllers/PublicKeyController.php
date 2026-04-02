<?php

namespace Jjoek\HybridEncryption\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Routing\Controller;
use Jjoek\HybridEncryption\Exceptions\EncryptionConfigException;
use Jjoek\HybridEncryption\Services\HybridEncryptionService;

class PublicKeyController extends Controller
{
    public function __construct(
        private HybridEncryptionService $encryptionService
    ) {}

    /**
     * Return the public key for frontend encryption.
     */
    public function __invoke(): JsonResponse
    {
        try {
            $publicKey = $this->encryptionService->getPublicKey();

            return response()->json([
                'publicKey' => $publicKey,
                'algorithm' => 'RSA-OAEP+AES-GCM-256',
                'keyFormat' => 'PEM',
            ]);
        } catch (EncryptionConfigException $e) {
            return response()->json([
                'error' => 'Encryption not configured',
                'message' => config('app.debug') ? $e->getMessage() : 'Public key not available',
            ], 500);
        }
    }
}
