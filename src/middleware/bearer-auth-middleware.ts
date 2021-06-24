import { BearerAuthContext } from "../types";
import { ClientError } from "@lindorm-io/errors";
import { Middleware } from "@lindorm-io/koa";
import { TokenIssuer } from "@lindorm-io/jwt";

interface MiddlewareOptions {
  audience?: string | Array<string>;
  issuer: string;
}

interface Options {
  maxAge?: string;
  scope?: Array<string>;
  subject?: string;
}

export const bearerAuthMiddleware =
  (middlewareOptions: MiddlewareOptions) =>
  (options: Options = {}): Middleware<BearerAuthContext> =>
  async (ctx, next): Promise<void> => {
    const metric = ctx.getMetric("auth");

    const { audience, issuer } = middlewareOptions;
    const { maxAge, scope, subject } = options;

    const { type, value: token } = ctx.getAuthorization() || {};

    if (type !== "Bearer") {
      metric.end();

      throw new ClientError("Invalid Authorization", {
        debug: { type, token },
        description: "Expected: Bearer",
        statusCode: ClientError.StatusCode.UNAUTHORIZED,
      });
    }

    try {
      ctx.token.bearerToken = ctx.jwt.verify(token, {
        audience,
        clientId: ctx.metadata.clientId ? ctx.metadata.clientId : undefined,
        deviceId: ctx.metadata.deviceId ? ctx.metadata.deviceId : undefined,
        issuer,
        maxAge,
        scope,
        subject,
        type: "access",
      });

      ctx.logger.debug("Bearer token validated", {
        bearerToken: TokenIssuer.sanitiseToken(token),
      });
    } catch (err) {
      metric.end();

      throw new ClientError("Invalid Authorization", {
        error: err,
        description: "Bearer token is invalid",
      });
    }

    metric.end();

    await next();
  };
