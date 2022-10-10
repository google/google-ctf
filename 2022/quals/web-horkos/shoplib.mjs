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

export const pickle = {
    PRIMITIVES: ['String', 'Number', 'Boolean'],
    loads: json => {
        const obj = {};
        for (const {key, type, value} of json) {
            if (type.match(/^pickled/)) {
                obj[key] = pickle.loads(value);
                const constructor = type.replace(/^pickled/, '');
                obj[key].__proto__ = (globalThis[constructor]||module[constructor]).prototype;
            } else {
                obj[key] = new globalThis[type](value);
            }
        }
        return obj;
    },
    dumps: obj => {
        const json = [];
        for (const key in obj) {
            const value = obj[key];
            const type = value.constructor.name;
            if (typeof type !== 'string') continue;
            if (typeof value == 'object' && !pickle.PRIMITIVES.includes(type)) {
                json.push({
                    key,
                    type: 'pickled' + type,
                    value: pickle.dumps(value)
                });
            } else if (typeof value !== 'undefined') {
                json.push({
                    key,
                    type,
                    value: globalThis[type].prototype.valueOf.call(value)
                });
            }
        }
        return json;
    }
};
const escapeHtml = (str) => str.includes('<') ? str.replace(/</g, c => `&#${c.charCodeAt()};`) : str;
const renderLines = (arr) => arr.reduce((p,c) => p+`
<div class="row">
<div class="col-xl-8">
  <p>${escapeHtml(c.key).toString()}</p>
</div>
<div class="col-xl-2">
  <p class="float-end">${escapeHtml(getValue(c.value, 'quantity').toString())}
  </p>
</div>
<div class="col-xl-2">
  <p class="float-end">${escapeHtml(getValue(c.value, 'price').toString())}
  </p>
</div>
<hr>
</div>`, '');

const getValue = (a, p) => p.split('/').reduce((arr,k) => arr.filter(e=>e.key==k)[0].value, a);

const renderOrder = (arr) => {
    return `
    <div class="container">
      <p class="my-5 mx-5" style="font-size: 30px;">Delivery Information</p>
      <div class="row">
        <ul class="list-unstyled">
          <li class="text-black">${escapeHtml(getValue(arr,'cart/address/street').toString())} ${escapeHtml(getValue(arr,'cart/address/number').toString())}</li>
          <li class="text-muted mt-1"><span class="text-black">Invoice</span> #${escapeHtml(getValue(arr, 'orderId').toString())}</li>
          <li class="text-black mt-1">${new Date().toDateString()}</li>
        </ul>
        <hr>
      </div>
      
      ${renderLines(getValue(arr, 'cart/items'))}

      <div class="row text-black">
        <div class="col-xl-12">
          <p class="float-end fw-bold">Total: $1337
          </p>
        </div>
        <hr style="border: 2px solid black;">
      </div>
      <div class="text-center" style="margin-top: 90px;">
        <p>Delivered by ${escapeHtml(getValue(arr, 'driver/username').toString())}. </p>
      </div>

    </div>
`;    
};

const DRIVERS = ['drivefast1', 'johnnywalker', 'onagbike'];

export const sendOrder = async (value, orders) => {
    const delivery = new DeliveryService(new Order(
        pickle.loads(JSON.parse(value))[0]
    ), orders);
    return delivery.sendOrder();
};

export class Driver {
    constructor(username, orders) {
        this.username = username;
        this.orders = orders;
    }
    async sendOrder(order) {
        order.driver = this;
        const pickledOrder = pickle.dumps(order);
        this.orders.push(pickledOrder);
        return true;
    }
};
export class DeliveryClient {
    constructor(pickledOrder) {
        this.pickledOrder = pickledOrder;
    }
    toString() {
        return renderOrder(this.pickledOrder);
    }
};
export class DeliveryService {
    constructor(order, orders) {
        this.order = order;
        this.orders = orders;
    }
    findDriver() {
        return new Driver(
            DRIVERS[Math.floor(Math.random() * DRIVERS.length)], this.orders);
    }
    async sendOrder() {
        const driver = this.findDriver();
        if (await driver.sendOrder(this.order)) {
            return this.order.orderId;
        }
    }
};
export class Order {
    constructor(cart) {
        this.cart = cart;
        this.driver = null;
        this.orderId = this.cart.shoppingCartId;
    }
};
export class ShoppingCart {
    constructor() {
        this.items = {};
        this.address = '';
        this.shoppingCartId = Math.floor(Math.random() * 1000000000000);
    }
    addItem(key, item) {
        this.items[key] = item;
    }
    removeItem(key) {
        delete this.items[key];
    }
};
export class Item {
    constructor(price) {
        this.price = price;
    }
    setQuantity(num) {
        this.quantity = num;
    }
};
export class Address {
    constructor(street, number, zip) {
        this.street = street;
        this.number = number;
        this.zip = zip;
    }
};

const module = {
    pickle,
    ShoppingCart, Order, Item, Address,
    DeliveryService, DeliveryClient
};
