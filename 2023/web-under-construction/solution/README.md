# Writeup for Under Construction

This challenge is based on two web applications which are running on different tech stacks.

## Registration and Login

Both applications support registration and login of users. While the registration endpoint of the Flask application can be accessed by anyone, the registration endpoint of the PHP application is protected by a secret token which has to be passed as a HTTP header. This token is shared between the Flask and the PHP application and can not be obtained by an attacker. There is a mechanism that Flask forwards the raw query parameter of registration requests to the PHP application to make sure that all accounts created on the Flask application also exist in the PHP application. Therefore, accounts created with the Flask application can also be used to login with the PHP application.

## Different user tiers (permission levels)

When creating an account, users can select their tier. The Flask application is aware of four different tiers: blue, red, green, gold. While the first three are considered low privileges, the gold tier is considered high privileges. The target for an attacker is to create an account (with known credentials) for the PHP applicatin that is gold tier. If they achieve that, they get the flag.

### Limiting of gold tier

The Flask application has a check that makes sure that the account is created on one of the unprivileged tiers. Even though the PHP application is missing such a check, attackers can not directly send authenticated registration requests for accounts in the gold tier to the PHP application because of the secret token in the HTTP header. 

## Bypass and exploit

An attacker has to send a request to the registration endpoint of the Flask application to create a low-privileged account there (to respect the gold tier permission check in the Flask application) which is then forwarded by Flask to the PHP application and leads to the creation of a high-privileged account in the PHP application (which does not have such a permission check).

This can be achieved by using the fact that the raw HTTP query is forwarded from Flask to PHP and both interpret HTTP queries with repeated parameters differently.

A HTTP query like `a=1&a=2` will be interpreted differently by Flask and PHP running on an Apache HTTP Server. In Flask, the parameter will be `1` (first occurence) while in PHP it will be `2` (last occurence).

This behavior can be used to craft a query like this: `username=username&password=password&tier=blue&tier=gold`. Posting this query to the Flask registration endpoint will lead to the creation of a low-privileged account in Flask and the creation of a high privileged account in PHP. This kind of attack is usually referred to as `HTTP parameter pollution`.

There are lots of tools to execute this POST request in an exploit. One example would be the following curl command:

```sh
curl -X POST http://<flask-challenge>/signup -d "username=username&password=password&tier=blue&tier=gold"
```
