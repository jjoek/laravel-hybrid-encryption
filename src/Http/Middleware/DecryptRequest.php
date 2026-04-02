<?php

namespace Jjoek\HybridEncryption\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Jjoek\HybridEncryption\Exceptions\DecryptionException;
use Jjoek\HybridEncryption\Exceptions\EncryptionConfigException;
use Jjoek\HybridEncryption\Services\HybridEncryptionService;
use Symfony\Component\HttpFoundation\Response;

class DecryptRequest
{
    public function __construct(
        private HybridEncryptionService $encryptionService
    ) {}

    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        // Check if request is encrypted
        if (!$this->isEncryptedRequest($request)) {
            return $next($request);
        }

        // Validate encryption algorithm header if present
        $algorithm = $request->header('X-Encryption-Algorithm');
        if ($algorithm && $algorithm !== 'RSA-OAEP+AES-GCM-256') {
            return response()->json([
                'error' => 'Unsupported encryption algorithm',
                'message' => 'Only RSA-OAEP+AES-GCM-256 is supported',
            ], 400);
        }

        try {
            $encryptedPayload = $request->only(['encryptedKey', 'encryptedData', 'iv']);

            if (empty($encryptedPayload['encryptedKey'])) {
                return response()->json([
                    'error' => 'Invalid encrypted request',
                    'message' => 'Missing encrypted payload fields (encryptedKey, encryptedData, iv)',
                ], 400);
            }

            $decryptedData = $this->encryptionService->decrypt($encryptedPayload);

            // Replace request data with decrypted payload
            $request->merge($decryptedData);

            // Remove encryption fields from the request
            $request->request->remove('encryptedKey');
            $request->request->remove('encryptedData');
            $request->request->remove('iv');

            // Mark request as decrypted (useful for debugging/logging)
            $request->attributes->set('hybrid_encryption_decrypted', true);

        } catch (EncryptionConfigException $e) {
            Log::error('Hybrid Encryption config error: ' . $e->getMessage());

            return response()->json([
                'error' => 'Encryption service not configured',
                'message' => config('app.debug') ? $e->getMessage() : 'Server encryption configuration error',
            ], 500);

        } catch (DecryptionException $e) {
            Log::warning('Hybrid Encryption decryption failed: ' . $e->getMessage());

            return response()->json([
                'error' => 'Decryption failed',
                'message' => config('app.debug') ? $e->getMessage() : 'Unable to decrypt request payload',
            ], 400);
        }

        return $next($request);
    }

    /**
     * Check if the request is marked as encrypted.
     */
    private function isEncryptedRequest(Request $request): bool
    {
        $encryptedHeader = $request->header('X-Encrypted');

        return $encryptedHeader === 'true' || $encryptedHeader === '1';
    }
}
