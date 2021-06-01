import { APIError } from "@lindorm-io/errors";
import { HttpStatus } from "@lindorm-io/core";

export class InvalidAuthorizationHeaderError extends APIError {
  public constructor(type: string) {
    super("Invalid Authorization Header", {
      details: "Expected header to be: Bearer",
      publicData: { type },
      statusCode: HttpStatus.ClientError.BAD_REQUEST,
    });
  }
}
