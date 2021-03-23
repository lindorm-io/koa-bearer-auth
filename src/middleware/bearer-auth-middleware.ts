import { IBearerTokenMiddlewareOptions, IKoaBearerAuthContext, TNext } from "../types";
import { InvalidAuthorizationHeaderError, InvalidBearerTokenError } from "../errors";
import { Permission, sanitiseToken } from "@lindorm-io/jwt";
import { getAuthorizationHeader } from "@lindorm-io/core";

export const bearerAuthMiddleware = (options: IBearerTokenMiddlewareOptions) => async (
  ctx: IKoaBearerAuthContext,
  next: TNext,
): Promise<void> => {
  const start = Date.now();

  const { logger, metadata } = ctx;

  const authorization = getAuthorizationHeader(ctx.get("Authorization"));

  if (authorization.type !== "Bearer") {
    throw new InvalidAuthorizationHeaderError(authorization.type);
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
    throw new InvalidBearerTokenError(verified.subject, verified.permission);
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
