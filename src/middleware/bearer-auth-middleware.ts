import { BearerAuthContext } from "../types";
import { ClientError } from "@lindorm-io/errors";
import { Middleware } from "@lindorm-io/koa";
import { TokenIssuer } from "@lindorm-io/jwt";
import { get } from "lodash";

interface MiddlewareOptions {
  audience?: string;
  issuer: string;
  maxAge?: string;
}

export interface BearerAuthOptions {
  nonce?: string;
  scope?: string;
  subject?: string;
}

export const bearerAuthMiddleware =
  (middlewareOptions: MiddlewareOptions) =>
  (options: BearerAuthOptions = {}): Middleware<BearerAuthContext> =>
  async (ctx, next): Promise<void> => {
    const metric = ctx.getMetric("auth");

    const { audience, issuer, maxAge } = middlewareOptions;
    const { nonce, scope, subject } = options;

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
        nonce: nonce ? get(ctx, nonce) : undefined,
        scope: scope ? get(ctx, scope) : undefined,
        subject: subject ? get(ctx, subject) : undefined,
        type: "access_token",
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
