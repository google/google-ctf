#!/bin/bash
# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


for i in {1..100}; do echo "waiting for mysql..."; sleep 5; if mysqladmin ping -h "$DB_HOST" --silent; then break; fi; done;
if [ $i -eq 100 ]; then
    echo "waiting for mysql failed"
    exit 1
fi

cd /lv
php artisan config:cache
yes | php artisan migrate:fresh
yes | php artisan db:seed --class=ProdDatabaseSeeder

php-fpm7.4
/usr/sbin/nginx -g "daemon off;"
