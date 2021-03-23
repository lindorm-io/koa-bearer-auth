# @lindorm-io/koa-bearer-auth
Bearer Auth middleware for @lindorm-io/koa applications

## Installation
```shell script
npm install --save @lindorm-io/koa-bearer-auth
```

### Peer Dependencies
This package has the following peer dependencies: 
* [@lindorm-io/jwt](https://www.npmjs.com/package/@lindorm-io/jwt)
* [@lindorm-io/key-pair](https://www.npmjs.com/package/@lindorm-io/key-pair)
* [@lindorm-io/koa](https://www.npmjs.com/package/@lindorm-io/koa)

## Usage

### Bearer Token Middleware

Prerequisite is to add a token issuer on the context. It can be done with the tokenIssuerMiddleware
```typescript
koaApp.addMiddleware(tokenIssuerMiddleware({
  issuer: "https://authentication.service/",
}));
```

Once the token issuer exists on the context, the middleware is ready to be used
```typescript
koaApp.addMiddleware(bearerAuthMiddleware({
  audience : "access",
  issuer : "https://authentication.service/",
}));
```
