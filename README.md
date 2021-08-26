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
  clockTolerance: 3, // OPTIONAL | number | giving some tolerance for time validation
  issuer: "https://authorization.service/", // REQURIED | uri | used for token validation
  maxAge: "10 minutes", // OPTIONAL | string | used in JWT validation
  type: "access_token", // OPTIONAL | string | token type
})

router.use(middleware({
  audiencePath: "metadata.clientId", // OPTIONAL | path to array | used in JWT validation 
  noncePath: "entity.authorizationSession.nonce", // OPTIONAL | path to string | used in JWT validation
  scopesPath: "entity.refreshSession.scopes", // OPTIONAL | path to array | used in JWT validation
  subjectPath: "entity.refreshSession.accountId", // OPTIONAL | path to string | used in JWT validation
}));

router.use(middleware({
  audience: ["444a9836-d2c9-470e-9270-071bfcb61346"], // OPTIONAL | Array<string> | used in JWT validation
  nonce: "6142a95bc7004df59e365e37516170a9", // OPTIONAL | string | used in JWT validation
  scopes: ["default"], // OPTIONAL | Array<string> | used in JWT validation
  subject: "c57ed8ee-0797-44dd-921b-3db030879ec6", // OPTIONAL | string | used in JWT validation
}));
```
