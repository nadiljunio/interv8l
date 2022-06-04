<?php

namespace App\Http\Controllers\API;

use App\Helpers\ResponseFormatter;
use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Support\Facades\Validator;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Laravel\Fortify\Rules\Password;

class UserController extends Controller {
    public function register(Request $request)
    {
        try {

            $validator = Validator::make($request->all(), [
                'name' => ['required', 'string', 'max:225'],
                'email' => ['required', 'string', 'email','max:225', 'unique:users'],
                'username' => ['required', 'string', 'max:225', 'unique:users'],
                'phone' => ['nullable', 'string', 'max:225'],
                'password' => ['required', 'string',new Password],
            ]); //$request->validate
           
            User::create([
                'name' =>$request->name, 
                'email' =>$request->email,
                'username' =>$request->username, 
                'phone' =>$request->phone,
                'password' => Hash::make($request->password), 
            ]); //User::create
            $user = User::where('email', $request->email)->first();

            $tokenResult = $user->createToken('authToken')->plainTextToken;
            return ResponseFormatter::success([
                'access_token' => $tokenResult,
                'token_type' => 'Bearer',
                'user' => $user
            ], 'User Registered');

            if($validator->fails()) {
                return response()->json($validator->errors(), 400);
            }
        } catch (Exception $error) {
            return ResponseFormatter::error([
                'message' => 'Something went wrong',
                'error' => $error
            ], 'Authentication Failed', 500);
        }
    }

    public function login (Request $request)
    {
        try {
            $validator = Validator::make($request->all(), [
                'email' => 'email|required',
                'password' => 'requred',
            ]);

            $credentials = request(['email', 'password']);
            if (!Auth::attempt($credentials)) {
                return ResponseFormatter::error([
                    'message' => 'unauthorized'
                ], 'Authentication Failed, 500');
            }

            $user = User::where('email', $request->email)->first();

            if(!Hash::check($request->password, $user->password, [] )) {
                throw new \Exception('invalid Credentials');
            }
            $tokenResult = $user->createToken('authToken')->plainTextToken;
            return ResponseFormatter::success ([
                'access_token' => $tokenResult,
                'token_type' => 'Bearer',
                'user' => $user
            ], 'authenticated');

            if($validator->fails()) {
                return response()->json($validator->errors(), 400);
            }
            }catch (Exception $error) {
                return ResponseFormatter::error([
                'message' => 'something went wrong',
                'error' => $error
            ], 'Authentication Failed, 500');

        }

    }

    public function fetch (Request $request)
    {
        return ResponseFormatter::success($request->user(), 'Data profile berhasil diambil');
    }
    
    public function updateProfile (Request $request)
    {
        $data = $request->all();
        
        $user = Auth::user();
        $user -> update($data);

        return ResponseFormatter::success($user, 'Profile updated');
    }
    
    public function logout (Request $request) 
    {
        $token = $request->user()->currentAccessToken()->delete();
        return ResponseFormatter::success($token, 'Token Revoked');
    }
}
