# Tech help
The Tech Help challenge.

# Build and run
To run it locally run the following commands:

```
npm install --prefix ./app ./app/
npm install --prefix ../web-typeselfsub-support/app/ ../web-typeselfsub-support/app/
sudo docker build . --tag typeselfsub:1.0
sudo docker run --publish 127.0.0.1:3306:3306 --detach --name typeselfsub typeselfsub:1.0
npm start --prefix ../web-typeselfsub-support/app/ ../web-typeselfsub-support/app/app.js &
DEV=1 npm start --prefix ./app/ ./app/app.js
```

