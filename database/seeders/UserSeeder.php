<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use App\Models\User;

class UserSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
        User::create(array(
            'role' => 'admin',
            'name' => 'adminarticle.com',
            'email' => 'admin@gmail.com',
            'password' => bcrypt('adminarticle')
        ));
    }
}