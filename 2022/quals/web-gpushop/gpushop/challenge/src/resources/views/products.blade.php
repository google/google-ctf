<!DOCTYPE html>
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

<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
    <head>
         @include('head')
    </head>
    <body>
        @include('nav')

        <main class="container">
            <div class="row row-cols-1 row-cols-md-3 g-4">
            @foreach ($products as $p)
                <div class="col">
                    <div class="card" style="width: 18rem;">
                      <img src="/img/{{$p->image}}" class="card-img-top" alt="...">
                      <div class="card-body">
                        <h5 class="card-title">{{$p->name}}</h5>
                        <p class="card-text">{{$p->description}}</p>
                        <ul class="list-group list-group-flush">
                            <li class="list-group-item text-end">{{$p->price}} &#x039e;</li>
                            <li class="list-group-item text-end"><form action="/cart/{{$p->id}}" method="POST">@csrf<input type="submit" class="btn btn-primary" value="Add to cart"></form></li>
                        </ul>
                      </div>
                    </div>
                </div>
            @endforeach
            </div>  
        </main>
        
</html>
