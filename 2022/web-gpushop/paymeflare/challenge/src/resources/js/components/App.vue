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
    <div>
        <nav class="navbar navbar-expand-md navbar-dark bg-dark mb-4">
          <div class="container-fluid">
            <a class="navbar-brand" href="/">paymeflare</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarCollapse" aria-controls="navbarCollapse" aria-expanded="false" aria-label="Toggle navigation">
              <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarCollapse">
              <ul class="navbar-nav me-auto mb-2 mb-md-0">
                <li class="nav-item">
                  <router-link :to="{name: 'home'}" class="nav-link active" aria-current="page">Home</router-link>
                </li>
                <li v-if="!login" class="nav-item">
                  <a class="nav-link" href="#" v-on:click="signIn">Login</a>
                </li>
               <li v-if="login" class="nav-item">
                  <router-link class="nav-link" :to="{name: 'account'}">Account</router-link>
               </li>                
               <li class="nav-item">
                  <router-link class="nav-link" :to="{name: 'doc'}">Documentation</router-link>
               </li> 
               <li v-if="login" class="nav-item">
                  <a class="nav-link" href="#" v-on:click="signOut">Logout</a>
               </li>
              </ul>
            </div>
          </div>
        </nav>
       <main class="container">
        <router-view></router-view>
      </main>
    </div>
</template>


<script>
export default {
    data() {
        return {
            login: false,
            user: null,
        }
    },
    methods: {
        signIn() {
            Vue.GoogleAuth.then(auth2 => {
                auth2.signIn().then(u => {
                    this.setUser(u);
                });
            });
        },
        signOut() {
            Vue.GoogleAuth.then(auth2 => {
                auth2.signOut();
                this.login = false;
                this.user = null;
                delete axios.defaults.headers.common['Authorization'];
            });
        },
        setUser(currentUser) {
            this.login = true;
            this.user = {
                id: currentUser.getId(),
                name: currentUser.getBasicProfile().getName(),
                id_token: currentUser.getAuthResponse().id_token
            }
            axios.defaults.headers.common['Authorization'] = 'Bearer ' + this.user.id_token;
            this.$root.$emit('login')
        }
    },    
    created() {
        Vue.GoogleAuth.then(auth2 => {
            if (auth2.isSignedIn.get()) {
                this.setUser(auth2.currentUser.get());
            }
        })
    }
}
</script>
