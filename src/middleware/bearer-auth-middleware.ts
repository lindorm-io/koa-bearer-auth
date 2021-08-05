import { BearerAuthContext } from "../types";
import { ClientError } from "@lindorm-io/errors";
import { Middleware } from "@lindorm-io/koa";
import { TokenIssuer } from "@lindorm-io/jwt";
import { get } from "lodash";

interface MiddlewareOptions {
  clockTolerance?: number;
  issuer: string;
  maxAge?: string;
  type?: Array<string>;
}

export interface BearerAuthOptions {
  audience?: string;
  nonce?: string;
  scopes?: string;
  subject?: string;
}

export const bearerAuthMiddleware =
  (middlewareOptions: MiddlewareOptions) =>
  (options: BearerAuthOptions = {}): Middleware<BearerAuthContext> =>
  async (ctx, next): Promise<void> => {
    const metric = ctx.getMetric("auth");

    const { clockTolerance, issuer, maxAge, type } = middlewareOptions;
    const { audience, nonce, scopes, subject } = options;

    const { type: tokenType, value: token } = ctx.getAuthorization() || {};

    if (tokenType !== "Bearer") {
      metric.end();

      throw new ClientError("Invalid Authorization", {
        debug: { tokenType, token },
        description: "Expected: Bearer",
        statusCode: ClientError.StatusCode.UNAUTHORIZED,
      });
    }

    try {
      ctx.token.bearerToken = ctx.jwt.verify(token, {
        audience: audience ? get(ctx, audience) : undefined,
        clockTolerance,
        issuer,
        maxAge,
        nonce: nonce ? get(ctx, nonce) : undefined,
        scopes: scopes ? get(ctx, scopes) : undefined,
        subject: subject ? get(ctx, subject) : undefined,
        type: type || ["access_token"],
      });

      ctx.logger.debug("Bearer token validated", {
        bearerToken: TokenIssuer.sanitiseToken(token),
      });
    } catch (err) {
      metric.end();

      throw new ClientError("Invalid Authorization", {
        error: err,
        debug: { middlewareOptions, options },
        description: "bearerToken is invalid",
      });
    }

    metric.end();

    await next();
  };
