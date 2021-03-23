import { IKoaAppContext } from "@lindorm-io/koa";
import { ITokenIssuerVerifyData, TokenIssuer } from "@lindorm-io/jwt";

export type TNext = () => Promise<void>;

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
