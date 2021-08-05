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
      audience: ["444a9836-d2c9-470e-9270-071bfcb61346"],
      expiry: "99 seconds",
      nonce: "6142a95bc7004df59e365e37516170a9",
      scopes: ["default", "edit"],
      subject: "c57ed8ee-0797-44dd-921b-3db030879ec6",
      type: "access_token",
    });

    middlewareOptions = {
      issuer: "issuer",
      maxAge: "90 minutes",
    };
    options = {
      audience: "metadata.clientId",
      nonce: "request.body.nonce",
      scopes: "request.body.scopes",
      subject: "request.body.subject",
    };

    ctx = {
      jwt,
      logger,
      metadata: {
        clientId: "444a9836-d2c9-470e-9270-071bfcb61346",
      },
      metrics: {},
      request: {
        body: {
          nonce: "6142a95bc7004df59e365e37516170a9",
          scopes: ["default"],
          subject: "c57ed8ee-0797-44dd-921b-3db030879ec6",
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
        subject: "c57ed8ee-0797-44dd-921b-3db030879ec6",
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
