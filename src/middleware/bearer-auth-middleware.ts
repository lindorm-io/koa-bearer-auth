import { IBearerTokenMiddlewareOptions, IKoaBearerAuthContext } from "../types";
import { InvalidAuthorizationHeaderError, InvalidBearerTokenError } from "../errors";
import { Middleware } from "koa";
import { Permission, sanitiseToken } from "@lindorm-io/jwt";
import { TNext } from "@lindorm-io/koa";
import { getAuthorizationHeader } from "@lindorm-io/core";

export const bearerAuthMiddleware = (options: IBearerTokenMiddlewareOptions): Middleware => {
  const { audience, issuer, issuerName } = options;

  return async (ctx: IKoaBearerAuthContext, next: TNext): Promise<void> => {
    const start = Date.now();
    const authorization = getAuthorizationHeader(ctx.get("Authorization"));

    if (authorization.type !== "Bearer") {
      throw new InvalidAuthorizationHeaderError(authorization.type);
    }

    const token = authorization.value;

    ctx.logger.debug("Bearer Token Auth identified", { token: sanitiseToken(token) });

    const verified = ctx.issuer[issuerName].verify({
      audience,
      clientId: ctx.metadata.clientId,
      deviceId: ctx.metadata.deviceId,
      issuer,
      token,
    });

    if (verified.permission && verified.permission === Permission.LOCKED) {
      throw new InvalidBearerTokenError(verified.subject, verified.permission);
    }

    ctx.token = {
      ...(ctx.token || {}),
      bearer: verified,
    };

    ctx.metrics = {
      ...(ctx.metrics || {}),
      bearerToken: Date.now() - start,
    };

    await next();
  };
};
