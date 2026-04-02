<?php

namespace Jjoek\HybridEncryption;

use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;
use Jjoek\HybridEncryption\Http\Controllers\PublicKeyController;
use Jjoek\HybridEncryption\Http\Middleware\DecryptRequest;
use Jjoek\HybridEncryption\Services\HybridEncryptionService;

class HybridEncryptionServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        // Merge config
        $this->mergeConfigFrom(
            __DIR__ . '/../config/hybrid-encryption.php',
            'hybrid-encryption'
        );

        // Register the service as a singleton
        $this->app->singleton(HybridEncryptionService::class, function ($app) {
            return new HybridEncryptionService();
        });

        // Register alias for easier access
        $this->app->alias(HybridEncryptionService::class, 'hybrid-encryption');
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        // Publish config
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/../config/hybrid-encryption.php' => config_path('hybrid-encryption.php'),
            ], 'hybrid-encryption-config');
        }

        // Register middleware alias
        $router = $this->app->make(Router::class);
        $middlewareAlias = config('hybrid-encryption.middleware_alias', 'decrypt.request');
        $router->aliasMiddleware($middlewareAlias, DecryptRequest::class);

        // Register routes if enabled
        if (config('hybrid-encryption.route.enabled', true)) {
            $this->registerRoutes();
        }
    }

    /**
     * Register the package routes.
     */
    protected function registerRoutes(): void
    {
        $routeConfig = config('hybrid-encryption.route');

        $this->app->make(Router::class)
            ->prefix($routeConfig['prefix'])
            ->middleware($routeConfig['middleware'])
            ->group(function (Router $router) use ($routeConfig) {
                $router->get($routeConfig['path'], PublicKeyController::class)
                    ->name($routeConfig['name']);
            });
    }
}
