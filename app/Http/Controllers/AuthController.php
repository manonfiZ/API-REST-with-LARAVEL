<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{

    /**
     * Register some user to our api
     * 
     * @param \Illuminate\Http\Request $request
     * @return \Illuminate\Http\Response
     * 
     */
    public function register(Request $request) {

        $fields = $request->validate([
            'name' => 'required|string',
            'email' => 'required|unique:users|email',
            'password' => 'required|alpha_num|confirmed|min:8'
        ]);

        $user = User::create([
            'name' => $fields['name'],
            'email' => $fields['email'],
            'password' => bcrypt($fields['password']),
        ]);

        $token = $user->createToken('my powerfull api')->plainTextToken;

        $response = [
            'user' => $user,
            'token access' => $token,
        ];

        return response()->json($response, 201);
    }

    /**
     * Log in or generate token to user to our api
     * 
     * @param \Illuminate\Http\Request $request
     * @return \Illuminate\Http\Response
     * 
     */
    public function login(Request $request) {

        $request->validate([
            'email' => 'required|email',
            'password' => 'required|alpha_num'
        ]);

        //Check user email
        $user = User::where('email', $request->email)->first();

        if(!$user || Hash::check($request->password, $user->password)){
            $token = $user->createToken('My powerfull api')->plainTextToken;
            $response = [
                // 'user' => $user,
                'token access' => $token,
            ];
    
            return response()->json($response, 201);
        }

        return response()->json(['message' => 'Bad credentials.'], 401);

    }


    /**
     * Log out some user to our api
     * 
     * @param \Illuminate\Http\Request $request
     * @return \Illuminate\Http\Response
     * 
     */
    public function logout(Request $request) {

        auth()->user()->tokens()->delete();
        $response = [
            'message' => 'Logged out.'
        ];

        return response()->json($response, 200);
    }

}
