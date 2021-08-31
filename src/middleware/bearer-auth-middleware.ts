import { BearerAuthContext } from "../types";
import { ClientError } from "@lindorm-io/errors";
import { Middleware } from "@lindorm-io/koa";
import { TokenIssuer } from "@lindorm-io/jwt";
import { get } from "lodash";

interface MiddlewareOptions {
  clockTolerance?: number;
  issuer: string;
  maxAge?: string;
  types?: Array<string>;
}

export interface BearerAuthOptions {
  audience?: string;
  audiences?: Array<string>;
  nonce?: string;
  permissions?: Array<string>;
  scopes?: Array<string>;
  subject?: string;
  subjectHint?: string;
  subjects?: Array<string>;

  fromPath?: {
    audience?: string;
    audiences?: string;
    nonce?: string;
    permissions?: string;
    scopes?: string;
    subjectHint?: string;
    subject?: string;
    subjects?: string;
  };
}

export const bearerAuthMiddleware =
  (middlewareOptions: MiddlewareOptions) =>
  (options: BearerAuthOptions = {}): Middleware<BearerAuthContext> =>
  async (ctx, next): Promise<void> => {
    const metric = ctx.getMetric("auth");

    const { clockTolerance, issuer, maxAge, types } = middlewareOptions;
    const {
      audience,
      audiences,
      nonce,
      permissions,
      scopes,
      subject,
      subjectHint,
      subjects,
      fromPath,
    } = options;

    const { type: tokenType, value: token } = ctx.getAuthorizationHeader() || {};

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
        audience: fromPath?.audience ? get(ctx, fromPath.audience) : audience,
        audiences: fromPath?.audiences ? get(ctx, fromPath.audiences) : audiences,
        clockTolerance,
        issuer,
        maxAge,
        nonce: fromPath?.nonce ? get(ctx, fromPath.nonce) : nonce,
        permissions: fromPath?.permissions ? get(ctx, fromPath.permissions) : permissions,
        scopes: fromPath?.scopes ? get(ctx, fromPath.scopes) : scopes,
        subject: fromPath?.subject ? get(ctx, fromPath.subject) : subject,
        subjects: fromPath?.subjects ? get(ctx, fromPath.subjects) : subjects,
        subjectHint: fromPath?.subjectHint ? get(ctx, fromPath.subjectHint) : subjectHint,
        types: types || ["access_token"],
      });

      ctx.logger.debug("Bearer token validated", {
        bearerToken: TokenIssuer.sanitiseToken(token),
      });
    } catch (err: any) {
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
