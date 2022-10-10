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
            @if ($items->isEmpty())
            <div class="alert alert-warning" role="alert">
                Your cart is empty!
            </div>
            @else
            <table class="table">
              <thead>
                <tr>
                  <th scope="col">Product</th>
                  <th scope="col">Price</th>
                  <th scope="col">Qty</th>
                  <th scope="col">Total</th>
                </tr>
              </thead>
              <tbody>
                @foreach ($items as $i)
                <tr>
                  <td>{{ $i->name }}</td>
                  <td>{{ $i->price }} &#x039e;</td>
                  <td>{{ $i->quantity }}</td>
                  <td>{{ $i->getPriceSum() }} &#x039e;</td>
                </tr>
                @endforeach
                <tr>
                    <td colspan="3"></td>
                    <td>{{ $subtotal }} &#x039e;</td>
                </tr>
                <tr>
                    <td colspan="3">Convenience fee</td>
                    <td>{{ $tax }} &#x039e;</td>
                </tr>
                <tr>
                    <td colspan="3"></td>
                    <td>{{ $total }} &#x039e;</td>
                </tr>           
              </tbody>
            </table>
            <div class="container pt-5">
                <div class="row justify-content-between">
                    <div class="col-4">
                        <form action="/cart/clear" method="POST">@csrf<input class="btn btn-danger"  type="submit" value="Clear cart"></form>
                    </div>                    
                    <div class="col-2">
                        <button type="button" class="btn btn-success" data-bs-toggle="modal" data-bs-target="#checkoutModal">Checkout</button>
                    </div>
                </div>
            </div>
            <div class="modal" tabindex="-1" id="checkoutModal">
              <form action="/cart/checkout" method="POST">
              @csrf
              <div class="modal-dialog">
                <div class="modal-content">
                  <div class="modal-header">
                    <h5 class="modal-title">Shipping details</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Cancel"></button>
                  </div>
                  <div class="modal-body">
                      <div class="mb-3">
                        <label for="message-text" class="col-form-label">Address:</label>
                        <textarea class="form-control" name="address"></textarea>
                      </div> 
                  </div>
                  <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <input type="submit" class="btn btn-primary" value="Submit"></button>
                  </div>
                </div>
              </div>
              </form>
            </div>            
            
            @endif
        </main>
        
</html>
