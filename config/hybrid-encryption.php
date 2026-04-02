<?php

return [
    /*
    |--------------------------------------------------------------------------
    | RSA Private Key
    |--------------------------------------------------------------------------
    |
    | The RSA private key used to decrypt the AES session keys.
    | This should be a PEM-formatted RSA private key.
    |
    | Generate with: openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
    |
    | Store the contents in your .env file (replace newlines with \n):
    | ENCRYPTION_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\nMIIEv..."
    |
    */
    'private_key' => env('ENCRYPTION_PRIVATE_KEY'),

    /*
    |--------------------------------------------------------------------------
    | RSA Public Key
    |--------------------------------------------------------------------------
    |
    | The RSA public key that will be shared with the frontend for encryption.
    | This should be a PEM-formatted RSA public key.
    |
    | Extract from private key: openssl rsa -pubout -in private_key.pem -out public_key.pem
    |
    | Store the contents in your .env file (replace newlines with \n):
    | ENCRYPTION_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----\nMIIBIj..."
    |
    */
    'public_key' => env('ENCRYPTION_PUBLIC_KEY'),

    /*
    |--------------------------------------------------------------------------
    | Route Configuration
    |--------------------------------------------------------------------------
    |
    | Configure the public key endpoint route.
    |
    */
    'route' => [
        'enabled' => env('ENCRYPTION_ROUTE_ENABLED', true),
        'prefix' => env('ENCRYPTION_ROUTE_PREFIX', 'api/v1'),
        'path' => env('ENCRYPTION_ROUTE_PATH', 'public-key'),
        'middleware' => ['api'],
        'name' => 'hybrid-encryption.public-key',
    ],

    /*
    |--------------------------------------------------------------------------
    | Middleware Alias
    |--------------------------------------------------------------------------
    |
    | The alias name for the decryption middleware.
    | Use this in your routes: Route::post('/send', ...)->middleware('decrypt.request');
    |
    */
    'middleware_alias' => 'decrypt.request',
];
