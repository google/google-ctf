#!/usr/bin/bash
for i in {1..100}; do echo "waiting for mysql..."; sleep 5; if mysqladmin ping -h "$DB_HOST" --silent; then break; fi; done;
if [ $i -eq 100 ]; then
    echo "waiting for mysql failed"
    exit 1
fi

while true; do
  node app.js
done

