import { BearerAuthContext } from "../types";
import { Middleware } from "@lindorm-io/koa";
import { Permission, sanitiseToken } from "@lindorm-io/jwt";
import { ClientError } from "@lindorm-io/errors";

interface Options {
  issuer: string;
}

export const bearerAuthMiddleware =
  (options: Options): Middleware<BearerAuthContext> =>
  async (ctx, next): Promise<void> => {
    const metric = ctx.getMetric("auth");

    const authorization = ctx.getAuthorization();

    if (authorization?.type !== "Bearer") {
      metric.end();

      throw new ClientError("Invalid Authorization", {
        description: "Expected: Bearer",
        statusCode: ClientError.StatusCode.UNAUTHORIZED,
      });
    }

    ctx.logger.debug("Bearer Token Auth identified", { token: sanitiseToken(authorization.value) });

    try {
      ctx.token.bearerToken = ctx.jwt.verify({
        audience: "access",
        clientId: ctx.metadata.clientId ? ctx.metadata.clientId : undefined,
        deviceId: ctx.metadata.deviceId ? ctx.metadata.deviceId : undefined,
        issuer: options.issuer,
        token: authorization.value,
      });
    } catch (err) {
      throw new ClientError("Invalid Authorization", { error: err });
    }

    if (ctx.token.bearerToken.permission && ctx.token.bearerToken.permission === Permission.LOCKED) {
      metric.end();

      throw new ClientError("Invalid Authorization", {
        debug: {
          subject: ctx.token.bearerToken.subject,
          permission: ctx.token.bearerToken.permission,
        },
        description: "Invalid permission",
        statusCode: ClientError.StatusCode.UNAUTHORIZED,
      });
    }

    metric.end();

    await next();
  };
