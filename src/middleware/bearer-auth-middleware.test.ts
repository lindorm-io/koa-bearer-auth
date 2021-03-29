import MockDate from "mockdate";
import { InvalidAuthorizationHeaderError, InvalidBearerTokenError } from "../errors";
import { InvalidTokenClientError, InvalidTokenDeviceError, TokenIssuer } from "@lindorm-io/jwt";
import { MissingAuthorizationHeaderError } from "@lindorm-io/core";
import { Permission } from "@lindorm-io/jwt";
import { bearerAuthMiddleware } from "./bearer-auth-middleware";
import { getTestKeystore, logger } from "../test";

MockDate.set("2020-01-01 08:00:00.000");

const tokenIssuer = new TokenIssuer({
  issuer: "mock-issuer",
  keystore: getTestKeystore(),
  // @ts-ignore
  logger,
});

const { id, token } = tokenIssuer.sign({
  audience: "mock-audience",
  clientId: "clientId",
  deviceId: "deviceId",
  expiry: "99 seconds",
  subject: "mock-subject",
  payload: { test: true },
});

describe("bearer-token-middlware.ts", () => {
  let options: any;
  let ctx: any;
  let next: any;

  beforeEach(() => {
    options = {
      audience: "mock-audience",
      issuer: "mock-issuer",
      issuerName: "issuerName",
    };
    ctx = {
      get: jest.fn(() => `Bearer ${token}`),
      logger: {
        debug: jest.fn(),
      },
      issuer: {
        issuerName: tokenIssuer,
      },
      metadata: {
        clientId: "clientId",
        deviceId: "deviceId",
      },
      metrics: {},
      token: {},
    };
    next = () => Promise.resolve();
  });

  test("should successfully validate bearer token auth", async () => {
    await expect(bearerAuthMiddleware(options)(ctx, next)).resolves.toBe(undefined);

    expect(ctx.token.bearer).toStrictEqual(
      expect.objectContaining({
        id,
        level: 0,
        payload: { test: true },
        subject: "mock-subject",
      }),
    );
  });

  test("should successfully validate when metadata is missing", async () => {
    ctx.metadata = {};

    await expect(bearerAuthMiddleware(options)(ctx, next)).resolves.toBe(undefined);
  });

  test("should throw error on wrong client metadata", async () => {
    ctx.metadata.clientId = "wrong";

    await expect(bearerAuthMiddleware(options)(ctx, next)).rejects.toThrow(expect.any(InvalidTokenClientError));
  });

  test("should throw error on wrong device metadata", async () => {
    ctx.metadata.deviceId = "wrong";

    await expect(bearerAuthMiddleware(options)(ctx, next)).rejects.toThrow(expect.any(InvalidTokenDeviceError));
  });

  test("should throw error on missing authorization header", async () => {
    ctx.get = jest.fn(() => undefined);

    await expect(bearerAuthMiddleware(options)(ctx, next)).rejects.toThrow(expect.any(MissingAuthorizationHeaderError));
  });

  test("should throw error on missing Bearer Token Auth", async () => {
    ctx.get = jest.fn(() => "Basic STRING");

    await expect(bearerAuthMiddleware(options)(ctx, next)).rejects.toThrow(expect.any(InvalidAuthorizationHeaderError));
  });

  test("should throw error on erroneous token verification", async () => {
    ctx.get = jest.fn(() => "Bearer wrong.wrong.wrong");

    await expect(bearerAuthMiddleware(options)(ctx, next)).rejects.toThrow();
  });

  test("should throw error on locked permission", async () => {
    const { token: newToken } = tokenIssuer.sign({
      audience: "mock-audience",
      permission: Permission.LOCKED,
      expiry: "99 seconds",
      subject: "mock-subject",
    });

    ctx = {
      ...ctx,
      get: jest.fn(() => `Bearer ${newToken}`),
    };

    await expect(bearerAuthMiddleware(options)(ctx, next)).rejects.toThrow(expect.any(InvalidBearerTokenError));
  });
});
