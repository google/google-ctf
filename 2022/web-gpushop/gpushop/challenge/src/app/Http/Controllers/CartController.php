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


namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\Product;
use App\Models\Order;

class CartController extends Controller
{
    public function index(Request $request)
    {
        if (\Cart::isEmpty()) {
            return view('cart', ['items' => \Cart::getContent()]);
        }
        
        $subtotal = \Cart::getSubTotal();
        $total = \Cart::getTotal();
        $condition = \Cart::getCondition('Scalper Tax');
        $tax = $condition->getCalculatedValue($subtotal);
        
        return view('cart', [
            'items' => \Cart::getContent(),
            'subtotal' => $subtotal,
            'total' => $total,
            'tax' => $tax
        ]);
    }
    
    public function add(Request $request, $id)
    {
        $p = Product::findOrFail($id);
        
        $condition = new \Darryldecode\Cart\CartCondition(array(
            'name' => 'Scalper Tax',
            'type' => 'tax',
            'target' => 'total',
            'value' => '15%',
            'attributes' => array(
                'description' => 'Scalper tax',
            )
        ));
        
        \Cart::condition($condition);        
        
        \Cart::add($p->id, $p->name, $p->price, 1, array());
        
        return redirect()->action([CartController::class, 'index']);
    }
    
    public function clear()
    {
        \Cart::clear();
        
        return redirect()->action([CartController::class, 'index']);
    }
    
    public function checkout(Request $request)
    {
        if (!\Cart::isEmpty()) {
            $order = new Order;
            $order->id = bin2hex(random_bytes(20));
            $order->address = $request->input('address');
            $order->wallet = $this->format_addr($request->header('X-Wallet'));
            $order->total = \Cart::getTotal();
            $order->items = \Cart::getContent()->toJson();
            $order->save();
            
            $request->session()->push('orders', $order->id);
            
            \Cart::clear();
        }
        
        return redirect()->action([OrderController::class, 'index']);
    }
    
    function format_addr($addr) {
        return '0x'.str_pad($addr, 40, '0', STR_PAD_LEFT);
    }        
}
