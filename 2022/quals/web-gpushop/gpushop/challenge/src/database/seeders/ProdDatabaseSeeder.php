<?php
// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


namespace Database\Seeders;

use Illuminate\Database\Seeder;
use App\Models\Product;


class ProdDatabaseSeeder extends Seeder
{
    /**
     * Seed the application's database.
     *
     * @return void
     */
    public function run()
    {
        Product::create([
            'name' => 'memetx 2000',
            'description' => 'Perfect for low budget memeing.',
            'price' => 0.91,
            'image' => 'gpu.png',
        ]);
        
        Product::create([
            'name' => 'memetx 2600',
            'description' => 'Getting serious about memeing? The memetx 2600 covers all your needs.',
            'price' => 1.39,
            'image' => 'gpu2.png',
        ]);
        
        Product::create([
            'name' => 'memetx 3000',
            'description' => 'For hardcore memers.',
            'price' => 1.83,
            'image' => 'gpu3.png',
        ]);
        
        
        Product::create([
            'name' => 'memetx 4000',
            'description' => 'It has RGB.',
            'price' => 2.69,
            'image' => 'gpu4.png',
        ]);
        
        
        Product::create([
            'name' => 'flag',
            'description' => 'A nice flag.',
            'price' => 1337,
            'image' => 'flag.png',
        ]);
    }
}
