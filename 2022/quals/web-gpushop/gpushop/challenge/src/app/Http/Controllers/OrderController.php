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

use App\Models\Order;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

function get_balance($addr) {
    // This function has 3 gateways. One is public and we got banned (cloudflare-eth.com),
    // the other was setup on cloudflare.com on a domain from the gctf, and the last
    // is running a eth node that kris setup and is only accessible from the kctf cluster
    // ip addresses.
    // Cloudflare's: https://eth.friendspacebookplusallaccessredpremium.com/v1/mainnet
    // Cloudflare's: https://cloudflare-eth.com/
    // Kris's: http://34.78.158.218:8545
    $res = Http::post("http://34.78.158.218:8545", [
        "jsonrpc" => "2.0",
        "method" => "eth_getBalance",
        "params" => [$addr, "latest"],
        "id" => 1
    ]);

    if ($res->ok()) {
        $data = $res->json();
        if (array_key_exists('error', $data)) {
            Log::error($res->body());
        } else {
            $b = $data['result'];
            return $b;
        }
    }

    return 0;
}

class OrderController extends Controller
{
    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function index(Request $request)
    {
        $orders = Order::find($request->session()->get('orders', []))->sortBy('created_at');

        return view('orders', [
            'orders' => $orders
        ]);
    }

    /**
     * Show the form for creating a new resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function create()
    {
        //
    }

    /**
     * Store a newly created resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function store(Request $request)
    {
        //
    }

    /**
     * Display the specified resource.
     *
     * @param  \App\Models\Order  $order
     * @return \Illuminate\Http\Response
     */
    public function show(Order $order)
    {
        $flag = '';

        $paid = $this->paid($order);
        if ($paid) {
            foreach(json_decode($order->items, true) as $i) {
                if ($i['name'] === 'flag') {
                    $flag = env('FLAG');
                }
            };
        }

        return view('order', [
            'order' => $order,
            'flag' => $flag,
            'paid' => $paid,
        ]);
    }

    public function paid(Order $order) {
        $b = get_balance($order->wallet);
        $t = gmp_mul((int)($order->total * 100), (int)1e16);

        return gmp_cmp($b, $t) >= 0;
    }

    /**
     * Show the form for editing the specified resource.
     *
     * @param  \App\Models\Order  $order
     * @return \Illuminate\Http\Response
     */
    public function edit(Order $order)
    {
        //
    }

    /**
     * Update the specified resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \App\Models\Order  $order
     * @return \Illuminate\Http\Response
     */
    public function update(Request $request, Order $order)
    {
        //
    }

    /**
     * Remove the specified resource from storage.
     *
     * @param  \App\Models\Order  $order
     * @return \Illuminate\Http\Response
     */
    public function destroy(Order $order)
    {
        //
    }
}
