<!--
 Copyright 2022 Google LLC

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
-->

<template>
<div v-if="account">
    <h2>Account</h2>
    <div class="col-md-7 col-lg-8">
        <form v-on:submit.prevent="onSubmit">
            <div class="mb-3">
              <label for="name" class="form-label">Name</label>
              <input type="text" id="name" class="form-control" :value="account.user.name" disabled>
            </div>
            <div class="mb-3">
                <label for="host" class="form-label">Domain</label>
                <input type="host" class="form-control" id="host" placeholder="foo.com" v-model="account.host">
            </div>
           <div class="mb-3">
                <label for="ip" class="form-label">IP</label>
                <input type="ip" class="form-control" id="host" placeholder="IP:Port" v-model="account.ip">
            </div>            
            <div class="mb-3">
              <label for="secret" class="form-label">Secret</label>
              <input type="text" id="secret" class="form-control" :value="account.secret" placeholder="Set your website to see the secret" disabled>
            </div>                
        <button type="submit" class="btn btn-primary">Save</button>
        </form>
        <div class="alert alert-danger" role="alert" v-if="err">
          {{ err }}
        </div>        
    </div> 
    <hr>
    <h2>Generated wallets</h2>
    <table class="table">
      <thead>
        <tr>
          <th scope="col">Public key</th>
          <th scope="col">Private key</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="w in account.wallets">
          <td>{{w.pubkey}}</td>
          <td>{{w.privkey}}</td>
        </tr>
      </tbody>
    </table>    
</div>
</template>

<script>
export default {
    data() {
        return {
            account: null,
            err: '',
        }
    },
    methods: {
        onSubmit() {
            this.err = '';
            axios.post('/api/account', {host: this.account.host, ip: this.account.ip}).then(response => {
                this.account.secret = response.data;
            }).catch(err => {
                this.err = err.response ? err.response.data : err;
            });
        }  
    },
    created() {
        this.$root.$on('login', () => {
            axios.get('/api/account').then(response => {
                this.account = response.data;
            });
        });
        axios.get('/api/account').then(response => {
            this.account = response.data;
        });        
    }
}
</script>
