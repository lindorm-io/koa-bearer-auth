import { ITokenIssuerVerifyData, TokenIssuer } from "@lindorm-io/jwt";
import { KoaContext } from "@lindorm-io/koa";

export interface BearerAuthContext extends KoaContext {
  issuer: {
    [key: string]: TokenIssuer;
  };
  token: {
    bearer: ITokenIssuerVerifyData<unknown>;
  };
}
