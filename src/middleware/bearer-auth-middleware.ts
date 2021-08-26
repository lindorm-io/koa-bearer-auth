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
  audience?: Array<string>;
  audiencePath?: string;
  nonce?: string;
  noncePath?: string;
  scopes?: Array<string>;
  scopesPath?: string;
  subject?: string;
  subjectPath?: string;
}

export const bearerAuthMiddleware =
  (middlewareOptions: MiddlewareOptions) =>
  (options: BearerAuthOptions = {}): Middleware<BearerAuthContext> =>
  async (ctx, next): Promise<void> => {
    const metric = ctx.getMetric("auth");

    const { clockTolerance, issuer, maxAge, type } = middlewareOptions;
    const { audience, audiencePath, nonce, noncePath, scopes, scopesPath, subject, subjectPath } = options;

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
        audience: audiencePath ? get(ctx, audiencePath) : audience,
        clockTolerance,
        issuer,
        maxAge,
        nonce: noncePath ? get(ctx, noncePath) : nonce,
        scopes: scopesPath ? get(ctx, scopesPath) : scopes,
        subject: subjectPath ? get(ctx, subjectPath) : subject,
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
