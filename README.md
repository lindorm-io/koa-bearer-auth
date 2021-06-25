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
* [@lindorm-io/koa-jwt](https://www.npmjs.com/package/@lindorm-io/koa-jwt)
* [@lindorm-io/winston](https://www.npmjs.com/package/@lindorm-io/winston)

## Usage

### Bearer Token Middleware

Prerequisite is to add [token issuer](https://www.npmjs.com/package/@lindorm-io/koa-jwt) to the context.

Once the token issuer exists on the context, the middleware is ready to be used
```typescript
const middleware = bearerAuthMiddleware({
  audience : "https://authentication.client/", // OPTIONAL | string | used in JWT validation
  issuer : "https://authorization.service/", // REQURIED | uri | used for token validation
  maxAge: "10 minutes", // OPTIONAL | string | used in JWT validation
})
router.use(middleware({
  nonce: "entity.authorizationSession.nonce", // OPTIONAL | path | used in JWT validation
  scope: "entity.refreshSession.scope", // OPTIONAL | path | used in JWT validation
  subject: "entity.refreshSession.accountId", // OPTIONAL | path | used in JWT validation
}));
```
