<?php

namespace App\Exceptions;

use Exception;
use Illuminate\Foundation\Exceptions\Handler as ExceptionHandler;
use PHPOpenSourceSaver\JWTAuth\Exceptions\JWTException;
use PHPOpenSourceSaver\JWTAuth\Exceptions\TokenExpiredException;
use PHPOpenSourceSaver\JWTAuth\Exceptions\TokenInvalidException;
use Throwable;

class Handler extends ExceptionHandler
{
    /**
     * A list of the exception types that are not reported.
     *
     * @var array<int, class-string<Throwable>>
     */
    protected $dontReport = [
        //
    ];

    /**
     * A list of the inputs that are never flashed for validation exceptions.
     *
     * @var array<int, string>
     */
    protected $dontFlash = [
        'current_password',
        'password',
        'password_confirmation',
    ];

    /**
     * Register the exception handling callbacks for the application.
     *
     * @return void
     */
    public function register()
    {
        $this->reportable(function (Throwable $e) {
            //
        });

        // exception handling JWT
        $this->renderable(function (Exception $e, $request) {
            if ($request->is('api/*')) {
                if ($e instanceof TokenExpiredException) {
                    return response()->json([
                        'message' => 'Token Expire.',
                    ], 401);
                } else if ($e instanceof TokenInvalidException) {
                    return response()->json([
                        'message' => 'Token Invalid.',
                    ], 401);
                } else if ($e instanceof JWTException) {
                    return response()->json([
                        'message' => 'Token Absen.',
                    ], 401);
                }
                // return response()->json([
                //     'message' => 'Unauthenticated.',
                // ], 401);
            }
        });
    }
}
