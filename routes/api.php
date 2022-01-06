<?php

use App\Http\Controllers\EmailVerificationController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\ArticleController;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\UserController;
use Illuminate\Foundation\Auth\EmailVerificationRequest;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

// Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
//     return $request->user();
// });

//Protect (authentication)
Route::group(['middleware' => ['auth:api', 'verified']], function() {
    Route::post('/logout', [AuthController::class, 'logout']);
    Route::post('/articles', [ArticleController::class, 'store']);
    Route::put('/articles/{id}', [ArticleController::class, 'update']);
});

//Protect (atuhentication and role admin)
Route::group(['middleware' => ['auth:api', 'role']], function() {
    Route::delete('/articles/{id}', [ArticleController::class, 'destroy']);
    Route::get('/user', [UserController::class, 'index']);
    Route::delete('/user/{id}', [UserController::class, 'destroy']);
});

//Public
Route::post('/register', [AuthController::class, 'register']);
Route::post('/login', [AuthController::class, 'login'])->middleware('throttle:login');
Route::get('/articles/search/{title}', [ArticleController::class, 'search']);
Route::get('/articles/{id}', [ArticleController::class, 'show']);
Route::get('/articles', [ArticleController::class, 'index']);

Route::get('/email/verify', function () {
    return view('auth.verify-email');
})->middleware('auth')->name('verification.notice');

Route::get('/email/verify/{id}/{hash}', function (EmailVerificationRequest $request) {
    $request->fulfill();

    return redirect('/home');
})->middleware(['auth', 'signed'])->name('verification.verify');

Route::post('/email/verification-notification', function (Request $request) {
    $request->user()->sendEmailVerificationNotification();

    return back()->with('message', 'Verification link sent!');
})->middleware(['auth', 'throttle:6,1'])->name('verification.send');