<?php

namespace App\Http;

use Illuminate\Foundation\Http\Kernel as HttpKernel;

class Kernel extends HttpKernel
{
    /**
     * The application's global HTTP middleware stack.
     *
     * These middleware are run during every request to your application.
     *
     * @var array<int, class-string|string>
     */
    protected $middleware = [
        // \App\Http\Middleware\TrustHosts::class,
        \App\Http\Middleware\TrustProxies::class,
        \Illuminate\Http\Middleware\HandleCors::class,
        \App\Http\Middleware\PreventRequestsDuringMaintenance::class,
        \Illuminate\Foundation\Http\Middleware\ValidatePostSize::class,
        \App\Http\Middleware\TrimStrings::class,
        \Illuminate\Foundation\Http\Middleware\ConvertEmptyStringsToNull::class,
    ];

    /**
     * The application's route middleware groups.
     *
     * @var array<string, array<int, class-string|string>>
     */
    protected $middlewareGroups = [
        'web' => [
            \App\Http\Middleware\EncryptCookies::class,
            \Illuminate\Cookie\middleware\AddQueuedCookiesToResponse::class,
            \Illuminate\Session\middleware\StartSession::class,
            \Illuminate\View\middleware\ShareErrorsFromSession::class,
            \App\Http\middleware\VerifyCsrfToken::class,
            \Illuminate\Routing\middleware\SubstituteBindings::class,
        ],

        'api' => [
            // \Laravel\Sanctum\Http\Middleware\EnsureFrontendRequestsAreStateful::class,
            'throttle:api',
            \Illuminate\Routing\middleware\SubstituteBindings::class,
        ],
    ];

    /**
     * The application's route middleware.
     *
     * These middleware may be assigned to groups or used individually.
     *
     * @var array<string, class-string|string>
     */
    protected $routeMiddleware = [
        'auth' => \App\Http\middleware\Authenticate::class,
        'auth.basic' => \Illuminate\Auth\middleware\AuthenticateWithBasicAuth::class,
        'auth.session' => \Illuminate\Session\middleware\AuthenticateSession::class,
        'cache.headers' => \Illuminate\Http\middleware\SetCacheHeaders::class,
        'can' => \Illuminate\Auth\middleware\Authorize::class,
        'guest' => \App\Http\middleware\RedirectIfAuthenticated::class,
        'password.confirm' => \Illuminate\Auth\middleware\RequirePassword::class,
        'signed' => \Illuminate\Routing\middleware\ValidateSignature::class,
        'throttle' => \Illuminate\Routing\middleware\ThrottleRequests::class,
        'verified' => \Illuminate\Auth\middleware\EnsureEmailIsVerified::class,
    ];
}
