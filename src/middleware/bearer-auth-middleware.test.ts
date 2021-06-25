import MockDate from "mockdate";
import { ClientError } from "@lindorm-io/errors";
import { Metric } from "@lindorm-io/koa";
import { bearerAuthMiddleware } from "./bearer-auth-middleware";
import { getTestJwt, logger } from "../test";

MockDate.set("2021-01-01T08:00:00.000Z");

const next = () => Promise.resolve();

describe("bearerAuthMiddleware", () => {
  let middlewareOptions: any;
  let options: any;
  let ctx: any;

  beforeEach(() => {
    const jwt = getTestJwt();
    const { token } = jwt.sign({
      audience: ["audience"],
      clientId: "444a9836-d2c9-470e-9270-071bfcb61346",
      deviceId: "87480227-f483-4450-83a6-3b4aa9c7e2a3",
      expiry: "99 seconds",
      nonce: "6142a95bc7004df59e365e37516170a9",
      scope: ["default", "edit"],
      subject: "subject",
      type: "access_token",
    });

    middlewareOptions = {
      audience: "audience",
      issuer: "issuer",
      maxAge: "90 minutes",
    };
    options = {
      nonce: "request.body.nonce",
      scope: "request.body.scope",
      subject: "request.body.subject",
    };
    ctx = {
      jwt,
      logger,
      metadata: {
        clientId: "444a9836-d2c9-470e-9270-071bfcb61346",
        deviceId: "87480227-f483-4450-83a6-3b4aa9c7e2a3",
      },
      metrics: {},
      request: {
        body: {
          nonce: "6142a95bc7004df59e365e37516170a9",
          scope: ["default"],
          subject: "subject",
        },
      },
      token: {},
    };

    ctx.getAuthorization = () => ({
      type: "Bearer",
      value: token,
    });
    ctx.getMetric = (key: string) => new Metric(ctx, key);
  });

  test("should successfully validate bearer token auth", async () => {
    await expect(bearerAuthMiddleware(middlewareOptions)(options)(ctx, next)).resolves.toBeUndefined();

    expect(ctx.token.bearerToken).toStrictEqual(
      expect.objectContaining({
        subject: "subject",
        token: expect.any(String),
      }),
    );
    expect(ctx.metrics.auth).toStrictEqual(expect.any(Number));
  });

  test("should throw error on missing Bearer Token Auth", async () => {
    ctx.getAuthorization = () => ({
      type: "Basic",
      value: "base64",
    });

    await expect(bearerAuthMiddleware(middlewareOptions)(options)(ctx, next)).rejects.toThrow(ClientError);
  });

  test("should throw error on erroneous token verification", async () => {
    ctx.getAuthorization = () => ({
      type: "Bearer",
      value: "jwt.jwt.jwt",
    });

    await expect(bearerAuthMiddleware(middlewareOptions)(options)(ctx, next)).rejects.toThrow(ClientError);
  });
});
