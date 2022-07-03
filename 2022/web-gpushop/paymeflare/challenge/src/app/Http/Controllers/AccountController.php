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

use kornrunner\Keccak;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use App\Models\Wallet;
use App\Models\Config;
use App\Services\Dataplane;


function hmac($host) {
    return hash_hmac('sha256', $host, config('app.paymeflare_key'));
}


class AccountController extends Controller
{
    public function index(Request $request) {
        $u = $request->user();
        $wallets = Wallet::select('pubkey', 'privkey')->where('account', $u->id)->get();
        $config = Config::find($u->id);
        $host = $config ? $config->host : '';
        $ip = $config ? $config->ip : '';
        $secret = $host ? hmac($host) : '';
               
        return ['user' => $u, 'wallets' => $wallets, 'host' => $host, 'ip' => $ip, 'secret' => $secret];
    }

    public function update(Request $request) {
        $u = $request->user();
        $config = Config::find($u->id);
        
        $host = strtolower($request->input('host'));
        $ip = $request->input('ip');
        
        if (preg_match('/^(?:[a-z0-9_-]+\.)+[a-z]+(?::[0-9]+)?$/i', $host) !== 1) {
            return response('Invalid host.', 400);
        }
        
        if (strpos($host, 'ctfcompetition.com') !== false) {
            return response('Invalid host.', 400);
        }        
        
        if (preg_match('/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]{1,5})?$/', $ip) !== 1) {
            return response('Invalid ip.', 400);
        }
               
        if (Config::where('host', $host)->first()) {
            return response('Domain already exists.', 400);
        }
        
        if (!Dataplane::update_backend($config ? $config->host : '', $host, $ip)) {
            return response("Can't add backend.", 400);
        }
     
        $config = Config::updateOrCreate(
            ['id' => $u->id],
            ['host' => $host, 'ip' => $ip]
        );
        
        return hmac($host);
    }
    
    public function genaddr(Request $request) {
        $h = strtolower($request->query('h'));
        
        if (strpos($h, ':') !== false) {
            list($h, $_port) = explode(':', $h);
        }
        
        $config = Config::where('host', $h)->first();
        
        if (!$config) {
            Log::Warning("config for ${h} not found");
        } else {
            Log::Info($config);
        }

        $res = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'secp256k1'
        ]);
        
        if (!$res) {
            Log::error('failed to generate key '.openssl_error_string());
            throw new \Exception('failed to generate key');
        }
       
        $details = openssl_pkey_get_details($res);
        
        $x = $details['ec']['x'];
        $y = $details['ec']['y'];
        $d = $details['ec']['d'];
        
        $pubkey = substr(Keccak::hash($x.$y, 256), -40);
        
        if ($config) {
            $w = new Wallet;
            $w->account = $config->id;
            $w->pubkey = $pubkey;
            $w->privkey = bin2hex($d);
            $w->save();
        }
        
        return $pubkey;
    }
}
