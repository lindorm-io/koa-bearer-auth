import MockDate from "mockdate";
import { ClientError } from "@lindorm-io/errors";
import { Metric } from "@lindorm-io/koa";
import { TokenIssuer } from "@lindorm-io/jwt";
import { bearerAuthMiddleware } from "./bearer-auth-middleware";
import { getTestKeystore, logger } from "../test";

MockDate.set("2021-01-01T08:00:00.000Z");

const tokenIssuer = new TokenIssuer({
  issuer: "https://auth.lindorm.io/",
  keystore: getTestKeystore(),
  logger,
});

const { id, token } = tokenIssuer.sign({
  audience: "audience",
  clientId: "444a9836-d2c9-470e-9270-071bfcb61346",
  deviceId: "87480227-f483-4450-83a6-3b4aa9c7e2a3",
  expiry: "99 seconds",
  scope: ["default", "edit"],
  subject: "mock-subject",
  type: "access",
});

const next = () => Promise.resolve();

describe("bearerAuthMiddleware", () => {
  let middlewareOptions: any;
  let ctx: any;

  beforeEach(() => {
    middlewareOptions = {
      audience: "audience",
      issuer: "https://auth.lindorm.io/",
    };
    ctx = {
      jwt: tokenIssuer,
      logger,
      metadata: {
        clientId: "444a9836-d2c9-470e-9270-071bfcb61346",
        deviceId: "87480227-f483-4450-83a6-3b4aa9c7e2a3",
      },
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
    await expect(bearerAuthMiddleware(middlewareOptions)()(ctx, next)).resolves.toBeUndefined();

    expect(ctx.token.bearerToken).toStrictEqual(
      expect.objectContaining({
        id,
        subject: "mock-subject",
      }),
    );
  });

  test("should successfully validate when metadata is missing", async () => {
    ctx.metadata = {};

    await expect(bearerAuthMiddleware(middlewareOptions)()(ctx, next)).resolves.toBeUndefined();
  });

  test("should throw error on wrong client metadata", async () => {
    ctx.metadata.clientId = "wrong";

    await expect(bearerAuthMiddleware(middlewareOptions)()(ctx, next)).rejects.toThrow(ClientError);
  });

  test("should throw error on wrong device metadata", async () => {
    ctx.metadata.deviceId = "wrong";

    await expect(bearerAuthMiddleware(middlewareOptions)()(ctx, next)).rejects.toThrow(ClientError);
  });

  test("should throw error on missing Bearer Token Auth", async () => {
    ctx.getAuthorization = () => ({
      type: "Basic",
      value: "base64",
    });

    await expect(bearerAuthMiddleware(middlewareOptions)()(ctx, next)).rejects.toThrow(ClientError);
  });

  test("should throw error on erroneous token verification", async () => {
    ctx.getAuthorization = () => ({
      type: "Bearer",
      value: "jwt.jwt.jwt",
    });

    await expect(bearerAuthMiddleware(middlewareOptions)()(ctx, next)).rejects.toThrow(ClientError);
  });

  test("should throw error on invalid audience", async () => {
    const { token: newToken } = tokenIssuer.sign({
      audience: "audience",
      expiry: "99 seconds",
      subject: "mock-subject",
      type: "wrong",
    });

    ctx.getAuthorization = () => ({
      type: "Bearer",
      value: newToken,
    });

    await expect(bearerAuthMiddleware(middlewareOptions)()(ctx, next)).rejects.toThrow(ClientError);
  });

  test("should throw when scope is invalid", async () => {
    await expect(
      bearerAuthMiddleware(middlewareOptions)({
        scope: ["default", "edit", "openid"],
      })(ctx, next),
    ).rejects.toThrow(ClientError);
  });
});
