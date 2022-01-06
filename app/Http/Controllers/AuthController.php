<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use App\Models\User;
use stdClass;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Auth\Events\Registered;

class AuthController extends Controller
{
    /**
     * Register
     * @OA\Post (
     *     path="/api/register",
     *     tags={"Authentication"},
     *     @OA\RequestBody(
     *         @OA\MediaType(
     *             mediaType="application/json",
     *             @OA\Schema(
     *                 @OA\Property(
     *                      type="object",
     *                      @OA\Property(
     *                          property="name",
     *                          type="string"
     *                      ),
     *                      @OA\Property(
     *                          property="email",
     *                          type="string"
     *                      ),
     *                      @OA\Property(
     *                          property="password",
     *                          type="string"
     *                      ),
     *                      @OA\Property(
     *                          property="password_confirmation",
     *                          type="string"
     *                      ),
     *                 ),
     *                 example={
     *                     "name":"example name",
     *                     "email":"example email",
     *                     "password":"example password",
     *                     "password_confirmation":"example password_confirmation"
     *                }
     *             )
     *         )
     *      ),
     *      @OA\Response(
     *          response=201,
     *          description="success",
     *          @OA\JsonContent(
     *              @OA\Property(property="message", type="string", example="Register Success"),
     *              @OA\Property(
     *                      property="data",
     *                      type="object",
     *                      @OA\Property(property="name", type="string", example="name"),
     *                      @OA\Property(property="email", type="string", example="email"),
     *                      @OA\Property(property="updated_at", type="string", example="2021-12-11T09:25:53.000000Z"),
     *                      @OA\Property(property="created_at", type="string", example="2021-12-11T09:25:53.000000Z"),
     *                      @OA\Property(property="id", type="number", example=1),
        *              ),
        *              @OA\Property(property="token", type="string", example="2|yqMYXWY3KYziZtVka00OVjC9q5FeOiJs4wcqbhGj"),
     *          )
     *      ),
     *      @OA\Response(
     *          response=422,
     *          description="Unprocessable Content",
     *          @OA\JsonContent(
     *              @OA\Property(property="msg", type="string", example="fail"),
     *          )
     *      )
     * )
     */
    /**
     * register account of the application.
     *
     * @param  \App\Http\Requests\UserRegisterRequest  $request
     * @return \Illuminate\Http\RedirectResponse|\Illuminate\Http\JsonResponse
     */
    public function register(Request $request) {
        $fields = $request->validate([
            'name' => 'required|string',
            'email' => 'required|string|unique:users,email',
            'password' => 'required|string|confirmed'
        ]);

        $user = User::create([
            'name' => $fields['name'],
            'email' => $fields['email'],
            'password' => bcrypt($fields['password'])
        ]);

        $token = $user->createToken('myapptoken')->accessToken;

        $res = new stdClass();
        $res->message = 'Register Success, Please Check Your Email for Verification';
        $res->data = $user;
        $res->token = $token;

        event(new Registered($user));

        return response()->json($res, 201);
    }

    /**
     * Login
     * @OA\Post (
     *     path="/api/login",
     *     tags={"Authentication"},
     *     @OA\RequestBody(
     *         @OA\MediaType(
     *             mediaType="application/json",
     *             @OA\Schema(
     *                 @OA\Property(
     *                      type="object",
     *                      @OA\Property(
     *                          property="email",
     *                          type="string"
     *                      ),
     *                      @OA\Property(
     *                          property="password",
     *                          type="string"
     *                      ),
     *                 ),
     *                 example={
     *                     "email":"example email",
     *                     "password":"example password"
     *                }
     *             )
     *         )
     *      ),
     *      @OA\Response(
     *          response=201,
     *          description="success",
     *          @OA\JsonContent(
     *              @OA\Property(property="message", type="string", example="Login Success"),
     *              @OA\Property(property="token", type="string", example="2|yqMYXWY3KYziZtVka00OVjC9q5FeOiJs4wcqbhGj"),
     *          )
     *      ),
     *      @OA\Response(
     *          response=401,
     *          description="Invalid email or password",
     *          @OA\JsonContent(
     *              @OA\Property(property="msg", type="string", example="fail"),
     *          )
     *      ),
     *      @OA\Response(
     *          response=422,
     *          description="Unprocessable Content",
     *          @OA\JsonContent(
     *              @OA\Property(property="msg", type="string", example="fail"),
     *          )
     *      )
     * )
     */
    /**
     * Handle a login request to the application.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\RedirectResponse|\Illuminate\Http\Response|\Illuminate\Http\JsonResponse
     *
     * @throws \Illuminate\Validation\ValidationException
     */
    public function login(Request $request) {
        $fields = $request->validate([
            'email' => 'required|string',
            'password' => 'required|string'
        ]);

        $user = User::where('email', $fields['email'])->first();

        if(!$user || !Hash::check($fields['password'], $user->password)) {
           
            return response([
                'message' => 'Invalid Email or Password'
            ], 401);
        }

        $token = $user->createToken('myapptoken')->accessToken;

        $res = new stdClass();
        $res->message = 'Login Success';
        $res->token = $token;

        RateLimiter::clear("login.".$request->ip());

        return response()->json($res, 201);
    }

    /**
     * Logout
     * @OA\Post(
     ** path="/api/logout",
     *   tags={"Authentication"},
     *   operationId="logout",
     *   security={{ "token": {} }},
     *      
     *   @OA\Response(
     *      response=200,
     *       description="Success",
     *       @OA\JsonContent(
     *          @OA\Property(property="message", type="string", example="Logged Out"),
     *       ),
     *   ),
     *   @OA\Response(
     *      response=401,
     *       description="Unauthorized",
     *   )
     *)
     **/
    /**
     * Log the user out of the application.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\RedirectResponse|\Illuminate\Http\JsonResponse
     */
    public function logout(Request $request)
    {
        $request->user()->currentAccessToken()->delete();
        
        return [
            'message' => 'Logged Out'
        ];
    }

}