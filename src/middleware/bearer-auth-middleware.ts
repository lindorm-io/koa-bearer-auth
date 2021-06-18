import { BearerAuthContext } from "../types";
import { Middleware } from "@lindorm-io/koa";
import { sanitiseToken } from "@lindorm-io/jwt";
import { ClientError } from "@lindorm-io/errors";
import { includes } from "lodash";

interface Options {
  issuer: string;
}

export const bearerAuthMiddleware =
  (options: Options) =>
  (requiredScope?: Array<string>): Middleware<BearerAuthContext> =>
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
        clientId: ctx.metadata.clientId,
        deviceId: ctx.metadata.deviceId,
        issuer: options.issuer,
        token: authorization.value,
      });

      ctx.logger.debug("Token validated", {
        bearerToken: sanitiseToken(authorization.value),
      });
    } catch (err) {
      metric.end();

      throw new ClientError("Invalid Authorization", {
        error: err,
        description: "Bearer token is invalid",
      });
    }

    if (ctx.token.bearerToken.permission && ctx.token.bearerToken.permission === "locked") {
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

    if (!requiredScope?.length) {
      metric.end();
      return await next();
    }

    for (const scope of requiredScope) {
      if (includes(ctx.token.bearerToken.scope, scope)) continue;

      throw new ClientError("Scope conflict", {
        data: { scope },
        debug: {
          expect: requiredScope,
          actual: ctx.token.bearerToken.scope,
        },
        description: "Expected scope not found on Bearer token",
        statusCode: ClientError.StatusCode.CONFLICT,
      });
    }

    metric.end();

    await next();
  };
