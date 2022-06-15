<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use PHPOpenSourceSaver\JWTAuth\Exceptions\JWTException;
use PHPOpenSourceSaver\JWTAuth\Exceptions\TokenExpiredException;
use PHPOpenSourceSaver\JWTAuth\Exceptions\TokenInvalidException;

class AuthController extends Controller
{
    public function __construct()
    {
        //time zone jakarta
        // date_default_timezone_set('asia/Jakarta');
        // date_default_timezone_set('Asia/Jakarta');

        $this->middleware('jwt.verify', ['except' => ['login', 'register']]);
    }

    public function login(Request $request)
    {
        $request->validate([
            'email' => 'required|string|email',
            'password' => 'required|string',
        ]);
        $credentials = $request->only('email', 'password');

        $token = AUTH::guard('api')->setTTL(1)->attempt($credentials);
        if (!$token) {
            return response()->json([
                'status' => 'error',
                'message' => 'Unauthorized',
            ], 401);
        }

        $user = AUTH::guard('api')->user();
        return response()->json([
            'status' => 'success',
            'user' => $user,
            'authorisation' => [
                'token' => $token,
                'expire_in' => gmdate("Y-m-d H:i:s", AUTH::guard('api')->payload()['exp'] * 1000),
            ]
        ]);
    }

    public function register(Request $request)
    {
        $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:6',
        ]);

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        $token = AUTH::guard('api')->login($user);
        return response()->json([
            'status' => 'success',
            'message' => 'User created successfully',
            'user' => $user,
            'authorisation' => [
                'token' => $token
            ]
        ]);
    }

    public function logout()
    {
        AUTH::guard('api')->logout();
        return response()->json([
            'status' => 'success',
            'message' => 'Successfully logged out',
        ]);
    }

    public function me()
    {
        $payload = AUTH::guard('api')->payload();

        $patloadRe = [
            "expire" => gmdate("Y-m-d H:i:s ", $payload('exp'))
        ];

        return response()->json([
            'status' => 'success',
            'payload' => $patloadRe,
            'user' => AUTH::guard('api')->user(),
        ]);
    }

    public function refresh()
    {
        return response()->json([
            'status' => 'success',
            'user' => AUTH::guard('api')->user(),
            'authorisation' => [
                'token' => AUTH::guard('api')->refresh(true, true),
                'type' => 'bearer',
            ]
        ]);
    }
}
