import MockDate from "mockdate";
import { InvalidAuthorizationHeaderError, InvalidBearerTokenError } from "../errors";
import { Metric } from "@lindorm-io/koa";
import { Permission } from "@lindorm-io/jwt";
import { bearerAuthMiddleware } from "./bearer-auth-middleware";
import { getTestKeystore, logger } from "../test";
import {
  InvalidTokenAudienceError,
  InvalidTokenClientError,
  InvalidTokenDeviceError,
  TokenIssuer,
} from "@lindorm-io/jwt";

MockDate.set("2020-01-01T08:00:00.000Z");

const tokenIssuer = new TokenIssuer({
  issuer: "https://auth.lindorm.io/",
  keystore: getTestKeystore(),
  logger,
});

const { id, token } = tokenIssuer.sign({
  audience: "access",
  clientId: "clientId",
  deviceId: "deviceId",
  expiry: "99 seconds",
  subject: "mock-subject",
  payload: { test: true },
});

const next = () => Promise.resolve();

describe("bearer-token-middlware.ts", () => {
  let options: any;
  let ctx: any;

  beforeEach(() => {
    options = {
      audience: "access",
      issuer: "https://auth.lindorm.io/",
      issuerName: "issuerName",
    };
    ctx = {
      jwt: tokenIssuer,
      logger,
      metadata: { clientId: "clientId", deviceId: "deviceId" },
      metrics: {},
      token: {},
    };
    ctx.getAuthorization = () => ({
      type: "Bearer",
      value: token,
    });
    ctx.getMetric = (key: string) => new Metric(ctx, key);
  });

  test("should successfully validate bearer token auth", async () => {
    await expect(bearerAuthMiddleware(options)(ctx, next)).resolves.toBeUndefined();

    expect(ctx.token.bearer).toStrictEqual(
      expect.objectContaining({
        id,
        payload: { test: true },
        subject: "mock-subject",
      }),
    );
  });

  test("should successfully validate when metadata is missing", async () => {
    ctx.metadata = {};

    await expect(bearerAuthMiddleware(options)(ctx, next)).resolves.toBeUndefined();
  });

  test("should throw error on wrong client metadata", async () => {
    ctx.metadata.clientId = "wrong";

    await expect(bearerAuthMiddleware(options)(ctx, next)).rejects.toThrow(expect.any(InvalidTokenClientError));
  });

  test("should throw error on wrong device metadata", async () => {
    ctx.metadata.deviceId = "wrong";

    await expect(bearerAuthMiddleware(options)(ctx, next)).rejects.toThrow(expect.any(InvalidTokenDeviceError));
  });

  test("should throw error on missing Bearer Token Auth", async () => {
    ctx.getAuthorization = () => ({
      type: "Basic",
      value: "base64",
    });

    await expect(bearerAuthMiddleware(options)(ctx, next)).rejects.toThrow(expect.any(InvalidAuthorizationHeaderError));
  });

  test("should throw error on erroneous token verification", async () => {
    ctx.getAuthorization = () => ({
      type: "Bearer",
      value: "jwt.jwt.jwt",
    });

    await expect(bearerAuthMiddleware(options)(ctx, next)).rejects.toThrow();
  });

  test("should throw error on invalid audience", async () => {
    const { token: newToken } = tokenIssuer.sign({
      audience: "wrong",
      expiry: "99 seconds",
      subject: "mock-subject",
    });

    ctx.getAuthorization = () => ({
      type: "Bearer",
      value: newToken,
    });

    await expect(bearerAuthMiddleware(options)(ctx, next)).rejects.toThrow(expect.any(InvalidTokenAudienceError));
  });

  test("should throw error on locked permission", async () => {
    const { token: newToken } = tokenIssuer.sign({
      audience: "access",
      permission: Permission.LOCKED,
      expiry: "99 seconds",
      subject: "mock-subject",
    });

    ctx.getAuthorization = () => ({
      type: "Bearer",
      value: newToken,
    });

    await expect(bearerAuthMiddleware(options)(ctx, next)).rejects.toThrow(expect.any(InvalidBearerTokenError));
  });
});
