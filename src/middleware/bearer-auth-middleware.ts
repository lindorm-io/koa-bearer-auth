import { BearerAuthContext } from "../types";
import { InvalidAuthorizationHeaderError, InvalidBearerTokenError } from "../errors";
import { Middleware } from "@lindorm-io/koa";
import { Permission, sanitiseToken } from "@lindorm-io/jwt";

interface Options {
  issuer: string;
}

export const bearerAuthMiddleware =
  (options: Options): Middleware<BearerAuthContext> =>
  async (ctx, next): Promise<void> => {
    const metric = ctx.getMetric("token");

    const authorization = ctx.getAuthorization();

    if (authorization?.type !== "Bearer") {
      throw new InvalidAuthorizationHeaderError(authorization.type);
    }

    ctx.logger.debug("Bearer Token Auth identified", { token: sanitiseToken(authorization.value) });

    ctx.token.bearer = ctx.jwt.verify({
      audience: "access",
      clientId: ctx.metadata.clientId ? ctx.metadata.clientId : undefined,
      deviceId: ctx.metadata.deviceId ? ctx.metadata.deviceId : undefined,
      issuer: options.issuer,
      token: authorization.value,
    });

    if (ctx.token.bearer.permission && ctx.token.bearer.permission === Permission.LOCKED) {
      throw new InvalidBearerTokenError(ctx.token.bearer.subject, ctx.token.bearer.permission);
    }

    metric.end();

    await next();
  };
