import { BearerAuthContext } from "../types";
import { InvalidAuthorizationHeaderError, InvalidBearerTokenError } from "../errors";
import { Permission, sanitiseToken } from "@lindorm-io/jwt";
import { Middleware } from "@lindorm-io/koa";

interface Options {
  audience: string;
  issuer: string;
  issuerName: string;
}

export const bearerAuthMiddleware =
  (options: Options): Middleware<BearerAuthContext> =>
  async (ctx, next): Promise<void> => {
    const start = Date.now();

    const authorization = ctx.getAuthorization();

    if (authorization?.type !== "Bearer") {
      throw new InvalidAuthorizationHeaderError(authorization.type);
    }

    ctx.logger.debug("Bearer Token Auth identified", { token: sanitiseToken(authorization.value) });

    ctx.token.bearer = ctx.jwt[options.issuerName].verify({
      audience: options.audience,
      clientId: ctx.metadata.clientId ? ctx.metadata.clientId : undefined,
      deviceId: ctx.metadata.deviceId ? ctx.metadata.deviceId : undefined,
      issuer: options.issuer,
      token: authorization.value,
    });

    if (ctx.token.bearer.permission && ctx.token.bearer.permission === Permission.LOCKED) {
      throw new InvalidBearerTokenError(ctx.token.bearer.subject, ctx.token.bearer.permission);
    }

    ctx.metrics.token = (ctx.metrics.token || 0) + (Date.now() - start);

    await next();
  };
