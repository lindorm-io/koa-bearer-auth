import { KeyPair, Keystore } from "@lindorm-io/key-pair";
import { InvalidTokenClientError, InvalidTokenDeviceError, TokenIssuer } from "@lindorm-io/jwt";
import { bearerAuthMiddleware } from "./bearer-auth-middleware";
import { v4 as uuid } from "uuid";
import { Permission } from "@lindorm-io/jwt";

const EC_PRIVATE_KEY =
  "-----BEGIN PRIVATE KEY-----\n" +
  "MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBGma7xGZpaAngFXf3\n" +
  "mJF3IxZfDpI+6wU564K+eehxX104v6dZetjSfMx0rvsYX/s6cO2P3GE7R95VxWEk\n" +
  "+f4EX0qhgYkDgYYABAB8cBfDwCi41G4kVW4V3Y86nIMMCypYzfO8gYjpS091lxkM\n" +
  "goTRS3LM1p65KQfwBolrWIdVrbbOILASf06fQsHw5gEt4snVuMBO+LS6pesX9vA8\n" +
  "QT1LjX75Xq2InnLY1VToeNmxkuM+oDZgqHOYwzfUhu+zZaA5AuEkqPi47TA9iCSY\n" +
  "VQ==\n" +
  "-----END PRIVATE KEY-----\n";

const EC_PUBLIC_KEY =
  "-----BEGIN PUBLIC KEY-----\n" +
  "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAfHAXw8AouNRuJFVuFd2POpyDDAsq\n" +
  "WM3zvIGI6UtPdZcZDIKE0UtyzNaeuSkH8AaJa1iHVa22ziCwEn9On0LB8OYBLeLJ\n" +
  "1bjATvi0uqXrF/bwPEE9S41++V6tiJ5y2NVU6HjZsZLjPqA2YKhzmMM31Ibvs2Wg\n" +
  "OQLhJKj4uO0wPYgkmFU=\n" +
  "-----END PUBLIC KEY-----\n";

const ecKey = new KeyPair({
  id: uuid(),
  created: new Date("2020-01-01 08:00:00.000"),
  expires: null,
  algorithm: "ES512",
  type: "ec",
  privateKey: EC_PRIVATE_KEY,
  publicKey: EC_PUBLIC_KEY,
});

const logger = {
  error: jest.fn(),
  warn: jest.fn(),
  info: jest.fn(),
  verbose: jest.fn(),
  debug: jest.fn(),
  silly: jest.fn(),
  createChildLogger: () => logger,
};

const keystore = new Keystore({ keys: [ecKey] });

const tokenIssuer = new TokenIssuer({
  issuer: "mock-issuer",
  keystore,
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
    };
    ctx = {
      get: jest.fn(() => `Bearer ${token}`),
      logger: {
        debug: jest.fn(),
      },
      issuer: { tokenIssuer },
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

    await expect(bearerAuthMiddleware(options)(ctx, next)).rejects.toStrictEqual(expect.any(InvalidTokenClientError));
  });

  test("should throw error on wrong device metadata", async () => {
    ctx.metadata.deviceId = "wrong";

    await expect(bearerAuthMiddleware(options)(ctx, next)).rejects.toStrictEqual(expect.any(InvalidTokenDeviceError));
  });

  test("should throw error on missing authorization header", async () => {
    ctx.get = jest.fn(() => undefined);

    await expect(bearerAuthMiddleware(options)(ctx, next)).rejects.toStrictEqual(
      expect.objectContaining({
        message: "Missing Authorization Header",
      }),
    );
  });

  test("should throw error on missing Bearer Token Auth", async () => {
    ctx.get = jest.fn(() => "Basic STRING");

    await expect(bearerAuthMiddleware(options)(ctx, next)).rejects.toStrictEqual(
      expect.objectContaining({
        message: "Invalid Authorization Header",
      }),
    );
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

    await expect(bearerAuthMiddleware(options)(ctx, next)).rejects.toStrictEqual(
      expect.objectContaining({
        message: "Invalid Bearer Token",
      }),
    );
  });
});
