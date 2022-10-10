/**
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

require('./bootstrap');

window.Vue = require('vue').default;

import VueRouter from 'vue-router'
Vue.use(VueRouter)

import { LoaderPlugin } from 'vue-google-login';
Vue.use(LoaderPlugin, {
    client_id: client_id
});

import Home from './components/Home'
import App from './components/App'
import Account from './components/Account'
import Doc from './components/Doc'


 
const router = new VueRouter({
    mode: 'history',
    routes: [
        { path: '/', name: 'home', component: Home },
        { path: '/account', name: 'account', component: Account },
        { path: '/doc', name: 'doc', component: Doc },
    ],
});

const app = new Vue({
    el: '#app',
    components: {App},
    router,
    data: {
        login: false
    }
});
