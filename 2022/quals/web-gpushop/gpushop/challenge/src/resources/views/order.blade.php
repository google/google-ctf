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
            <div>
                <h4 class="mb-3">Order Information</h4>
                <div>#ID {{ $order->id }}</div>
                <div>Total {{ $order->total }} &#x039e;</div>
                <div>Shipping Address: {{ $order->address }}</div>
                <hr class="my-4">
                <h4 class="mb-3">Payment</h4>
                <div>Please send your payment to the following address:</div>
                <div><a href="https://etherscan.io/address/{{$order->wallet}}">{{ $order->wallet }}</a></div>
            </div>
            <br>
            <div>
                @if ($paid)
                <div class="alert alert-primary" role="alert">Payment confirmed.</div>
                @endif
                @if ($flag)
                <div class="alert alert-success" role="alert">The flag is {{ $flag }}</div>
                @endif                
            </div>
        </main>
        
</html>
