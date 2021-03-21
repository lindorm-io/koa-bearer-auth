import { APIError, HttpStatus, TPromise, getAuthorizationHeader } from "@lindorm-io/core";
import { IKoaAppContext } from "@lindorm-io/koa";
import { ITokenIssuerVerifyData, Permission, TokenIssuer, sanitiseToken } from "@lindorm-io/jwt";

export interface IKoaBearerAuthContext extends IKoaAppContext {
  issuer: {
    tokenIssuer: TokenIssuer;
  };
  token: {
    bearer: ITokenIssuerVerifyData;
  };
}

export interface IBearerTokenMiddlewareOptions {
  audience: string;
  issuer: string;
}

export const bearerAuthMiddleware = (options: IBearerTokenMiddlewareOptions) => async (
  ctx: IKoaBearerAuthContext,
  next: TPromise<void>,
): Promise<void> => {
  const start = Date.now();

  const { logger, metadata } = ctx;

  const authorization = getAuthorizationHeader(ctx.get("Authorization"));

  if (authorization.type !== "Bearer") {
    throw new APIError("Invalid Authorization Header", {
      details: "Expected header to be: Bearer",
      publicData: { header: authorization.type },
      statusCode: HttpStatus.ClientError.BAD_REQUEST,
    });
  }

  const token = authorization.value;

  logger.debug("Bearer Token Auth identified", { token: sanitiseToken(token) });

  const verified = ctx.issuer.tokenIssuer.verify({
    audience: options.audience,
    clientId: metadata.clientId,
    deviceId: metadata.deviceId,
    issuer: options.issuer,
    token,
  });

  if (verified.permission && verified.permission === Permission.LOCKED) {
    throw new APIError("Invalid Bearer Token", {
      details: "Subject is locked",
      publicData: {
        subject: verified.subject,
        permission: verified.permission,
      },
      statusCode: HttpStatus.ClientError.FORBIDDEN,
    });
  }

  ctx.token = {
    ...(ctx.token || {}),
    bearer: verified,
  };

  ctx.metrics = {
    ...(ctx.metrics || {}),
    bearerToken: Date.now() - start,
  };

  await next();
};
