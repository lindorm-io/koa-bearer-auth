import { IKoaAppContext } from "@lindorm-io/koa";
import { ITokenIssuerVerifyData, TokenIssuer } from "@lindorm-io/jwt";

export interface IKoaBearerAuthContext extends IKoaAppContext {
  issuer: {
    [key: string]: TokenIssuer;
  };
  token: {
    bearer: ITokenIssuerVerifyData;
  };
}
