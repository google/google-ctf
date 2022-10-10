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
            @if ($orders->isEmpty())
            <div class="alert alert-warning" role="alert">
                Buy something!
            </div>
            @endif            
            <ul class="list-group">
            @foreach ($orders as $o)
              <li class="list-group-item"><a href="/order/{{ $o->id }}">{{ $o->id }}</a></li>
            @endforeach
            </ul>
        </main>
        
</html>
