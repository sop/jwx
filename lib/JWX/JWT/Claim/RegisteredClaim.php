<?php

namespace JWX\JWT\Claim;


abstract class RegisteredClaim extends Claim
{
	const NAME_ISSUER = "iss";
	const NAME_SUBJECT = "sub";
	const NAME_AUDIENCE = "aud";
	const NAME_EXPIRATION_TIME = "exp";
	const NAME_NOT_BEFORE = "nbf";
	const NAME_ISSUED_AT = "iat";
	const NAME_JWT_ID = "jti";
}
