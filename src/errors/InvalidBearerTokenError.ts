import { APIError } from "@lindorm-io/errors";
import { HttpStatus } from "@lindorm-io/core";

export class InvalidBearerTokenError extends APIError {
  constructor(subject: string, permission: string) {
    super("Invalid Bearer Token", {
      details: "Subject is locked",
      publicData: { subject, permission },
      statusCode: HttpStatus.ClientError.FORBIDDEN,
    });
  }
}
