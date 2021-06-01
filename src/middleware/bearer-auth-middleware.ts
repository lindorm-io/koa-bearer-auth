import { BearerAuthContext } from "../types";
import { InvalidAuthorizationHeaderError, InvalidBearerTokenError } from "../errors";
import { Permission, sanitiseToken } from "@lindorm-io/jwt";
import { getAuthorizationHeader, Middleware } from "@lindorm-io/koa";

interface Options {
  audience: string;
  issuer: string;
  issuerName: string;
}

export const bearerAuthMiddleware = (options: Options): Middleware<BearerAuthContext> => {
  const { audience, issuer, issuerName } = options;

  return async (ctx, next): Promise<void> => {
    const start = Date.now();
    const authorization = getAuthorizationHeader(ctx.get("Authorization"));

    if (authorization.type !== "Bearer") {
      throw new InvalidAuthorizationHeaderError(authorization.type);
    }

    const token = authorization.value;

    ctx.logger.debug("Bearer Token Auth identified", { token: sanitiseToken(token) });

    const verified = ctx.issuer[issuerName].verify({
      audience,
      clientId: ctx.metadata.clientId ? ctx.metadata.clientId : undefined,
      deviceId: ctx.metadata.deviceId ? ctx.metadata.deviceId : undefined,
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

    ctx.metrics.bearerToken = Date.now() - start;

    await next();
  };
};
