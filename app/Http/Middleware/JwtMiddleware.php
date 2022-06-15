<?php

namespace App\Http\Middleware;

use Closure;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use PHPOpenSourceSaver\JWTAuth\Exceptions\JWTException;
use PHPOpenSourceSaver\JWTAuth\Exceptions\TokenExpiredException;
use PHPOpenSourceSaver\JWTAuth\Exceptions\TokenInvalidException;
use PHPOpenSourceSaver\JWTAuth\Facades\JWTAuth;
use PHPOpenSourceSaver\JWTAuth\Http\Middleware\BaseMiddleware;

class JwtMiddleware extends BaseMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure(\Illuminate\Http\Request): (\Illuminate\Http\Response|\Illuminate\Http\RedirectResponse)  $next
     * @return \Illuminate\Http\Response|\Illuminate\Http\RedirectResponse
     */
    public function handle(Request $request, Closure $next)
    {
        try {
            $user = JWTAuth::parseToken()->authenticate();
        } catch (Exception $e) {
            if ($e instanceof TokenInvalidException) {
                $status     = 401;
                $message    = 'This token is invalid. Please Login';
                return response()->json(compact('status', 'message'), 401);
            } else if ($e instanceof TokenExpiredException) {
                // If the token is expired, then it will be refreshed and added to the headers
                try {
                    $refreshed = AUTH::refresh(JWTAuth::getToken());
                    $user = JWTAuth::setToken($refreshed)->toUser();
                } catch (JWTException $e) {
                    return response()->json([
                        'code'   => 404,
                        'message' => 'Token cannot be refreshed, please Login again'
                    ]);
                }
                // $message = 'Token Expire';
                // return response()->json(compact('message'), 404);
            } else {
                $message = 'Authorization Token not found';
                return response()->json(compact('message'), 404);
            }
        }
        return $next($request);
    }
}
