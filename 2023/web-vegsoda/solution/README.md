# Veggie Soda

This challenge is based off of using a deserialization gadget to deliver an XSS payload in spite of CSRF protections. 


## Vegetable Soda Social Media

The application mimics a rough connection hub for people who like vegetable soda. You can send custom "sodas" as a clunky messaging mechanism, make posts that serve as a private notes repository, and report suspicious URLs to administration. If you attempt to message an admin with your soda, or attempt to put suspicious HTML characters into your post, you'll get hit with a warning for comitting a violation. Accumulate enough warnings and your soda or post making privileges are removed. Admins/privileged users get a special "status" function - but standard users don't have that same functionality.

These different functionalities interface with a database in the back-end through classes. The OOP design interacts with a queue to manage DB submission and retrieval. All posts, sodas, violations ("vios") and statuses are submitted to the queue and processed when the queue is full. The queue will iterate through each item to be processed and assign it to the user in question. Later, the app pushes any new sodas/vios/posts into the DB. 

## The Status Page
The status endpoint is completely inaccessible to standard users. Notably, it uses `router.all`, which ostensibly handles all GET, PUT, POST, OPTIONS, and DELETE requests. The route will change a premium user's status either by using the request body or the request query parameters, if present. More specifically, this endpoint gives you control over the type, which is used by the queue to determine how to process the item. Through the status endpoint you have control over an item in the queue and how it should be processed. If you could make an admin CSRF a request to this endpoint, then you could inject an item into the queue which can be processed however you'd like. 

But what kind of request? The application does not opt into CORS, so only simple requests will be routed. That removes PUT and DELETE requests, and other pre-flights. So maybe a GET or a POST is the request to make.

Despite that, however, the CSRF middleware will likely block you from actually performing a CSRF attack, by vetting all POST requests and vetting all GET requests that have query parameters. You will need to determine a way to bypass the CSRF middleware to actually talk to the endpoint in question. 


## The CSRF bypass
There exists CSRF middleware that is automatically applied to all GET and POST requests. 

```ts
    csrf_protections(): Middleware {
        const csrf_func = async (ctx: Context, next: () => Promise<void>): Promise<void> => {
            if (ctx.request.method === "GET"){
                const get_success = await getCsrfMiddleware(ctx, this.key);
                if (!get_success) {
                    return ctx.response.redirect("/");
                }
            } else if (ctx.request.method === "POST"){
                const post_success = await postCsrfMiddleware(ctx, this.key);
                if (!post_success){
                    return ctx.response.redirect("/");
                }
            }
            await next();
        }
        return csrf_func as Middleware;
    }
```

With this middleware, a simple request CSRF isn't possible, but it can be bypassed.

According to [Oak's source code](https://github.com/oakserver/oak/blob/main/router.ts#L281), a router is set to handle HEAD requests as GET requests with no response body - a common workaround that isn't unique to Oak. Instead of a specific handler that deals with HEAD reqs, they're simply given to the GET handler but the app just removes the response body. This quirk honors the HTTP specs without too much of overhead for developers to think about making their own HEAD middleware (even though Oak definitely provides that). To summarize, a HEAD request is therefore treated by the app as a GET request.

The problem lies with the CSRF middleware, and how it _checks_ the methods of the request. Even though a HEAD request is routed to the GET handler, the CSRF middleware won't apply the protections because its if check (`ctx.request.method === "GET"`) returns false (`HEAD != GET`). Therefore, the middleware ignores the HEAD request and believes it to be CSRF-safe. 

You can use this to send a totally legit GET request that doesn't look like a GET request in order to leverage the `/status` endpoint's desired functionality to inject into the processing queue. 

## The Typescript Deserialization chain

Injecting into the queue is so important because that kicks off a potential creation of a post or a soda that can be viewed by an admin user. The queue will first attempt to deserialize a string and process the class accordingly. The serialization/deserialization library is SuperSerial, which follows closely after PHP's unserialize API. However, SuperSerial doesn't deal in functions just yet, meaning that deserialization-based RCE a la Python's Pickle isn't possible. 

SuperSerial does deal in classes, which is what the queue processes. The available classes are:

```
Log
Post
Soda
Warning
Vio
```

You can't go the easy route and inject a rogue soda or post that easily - during processing, all sodas and posts are HTML-escaped, rendering your XSS exploit invalid. So, you need to find some way to push your post/soda into the user's array so it can be inserted into the DB, whilst not actually calling the sanitizing/escaping functions during that process to have a valid XSS out the other side. So, a direct serialized post/soda wouldn't work, but what about a chain? 

It's worth noting that the other classes actually share function names. They perform different things, but they have similar names - and this typically wouldn't be a problem for a type-cautious language, which has generics to assert types... except that all classes in there aren't generic, so generic constructors can't be used, and therefore the program can't assert types in certain situations when dealing with the serializer. This isn't a problem with the serializer, but rather an oversight into the use of generics and type assertions in TypeScript. 

What this means for us is that we have the possibility of utilizing popchain-esque capabilities in TypeScript, by leveraging same-named functions to chain together bits of code into a desired result. In this case, the desired result is stored XSS.

This additionally means that the queue may consider a deserialized class be processed as a specific class even though it's a different one. This can usually cause errors, but in this case, we can take advantage of that and leverage it as the beginning gadget to the deserialization chain. 

While it may be possible to create different chains, the serialization chain that was used in the intended solution was as follows:

1. `Log` class, which has an `apply` method that subsequently calls `this.e.validate()` in which `e = any` is a property in the class, that we specify to be a...
2. `Vio` class, which has a `validate` method that can subsequently call `this.warning.resolve()` under an if check, where `warning = Warning` is a property in the class, that we can specify (because no type-assertion!) to be a...
3. `Soda` class, which has a `resolve` method that takes a `user: User` argument and pushes itself to the user's soda array. This means that the soda will get pushed into the user's objects but it _doesnt_ get sanitized/escaped.

The last bit that's needed is a way to call `Log.apply()`, which happens if your serialized string is processed as a `Post`.

Through this you can chain together the bits of code and push a not-escaped XSS into an arbitrary user's array. Therefore, all you need now is to have the admin visit that rogue soda you made, and pop XSS. 

The final payload is as so.


```html

<html>
<head>
</head>
<body>
<script>
var url  = 'https://vegsoda-web.2023.ctfcompetition.com/status?type=Post&content=' + encodeURIComponent(
        `Log {"id": "464ae41a-7e73-4a14-8e59-8d79ee26d8a1","date": $1,"e": $2};Date(1685983017847);Vio {"id": "3ecf5b18-9586-4d6b-972f-38325ebf51ce","level": "POP RET","userid":"BLAAAH", "warning": $3}; Soda {"id": "b52b0a50-569b-4655-ad12-e8e6b09c3002","dest": "admin","src": "ME","variety": "Carrot","note": "<script>alert(1)</script>"}`
    );

fetch(url, {method:'HEAD'}).then(console.log)

</script>

</body>
</html>
```