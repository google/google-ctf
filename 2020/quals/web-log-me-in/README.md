# Log-Me-In
the log-me-in challenge

# Build and run
You can run this locally using the following commands:

```
npm install --prefix ./app ./app/
sudo docker build . --tag typeselfsub:1.0
sudo docker run --publish 127.0.0.1:3306:3306 --detach --name typeselfsub typeselfsub:1.0
DEV=1 npm start --prefix ./app/ ./app/app.js
```

