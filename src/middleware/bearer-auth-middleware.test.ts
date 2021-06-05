import MockDate from "mockdate";
import { InvalidAuthorizationHeaderError, InvalidBearerTokenError } from "../errors";
import { InvalidTokenClientError, InvalidTokenDeviceError, TokenIssuer } from "@lindorm-io/jwt";
import { Permission } from "@lindorm-io/jwt";
import { bearerAuthMiddleware } from "./bearer-auth-middleware";
import { getTestKeystore, logger } from "../test";

MockDate.set("2020-01-01T08:00:00.000Z");

const tokenIssuer = new TokenIssuer({
  issuer: "mock-issuer",
  keystore: getTestKeystore(),
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

const next = () => Promise.resolve();

describe("bearer-token-middlware.ts", () => {
  let options: any;
  let ctx: any;

  beforeEach(() => {
    options = {
      audience: "mock-audience",
      issuer: "mock-issuer",
      issuerName: "issuerName",
    };
    ctx = {
      getAuthorization: () => ({
        type: "Bearer",
        value: token,
      }),
      logger: {
        debug: jest.fn(),
      },
      jwt: {
        issuerName: tokenIssuer,
      },
      metadata: {
        clientId: "clientId",
        deviceId: "deviceId",
      },
      metrics: {},
      token: {},
    };
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

  test("should throw error on locked permission", async () => {
    const { token: newToken } = tokenIssuer.sign({
      audience: "mock-audience",
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
