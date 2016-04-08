<?php

namespace JWX\JOSE\Parameter;


abstract class RegisteredParameter extends Parameter
{
	const NAME_TYPE = "typ";
	const NAME_CONTENT_TYPE = "cty";
	const NAME_ALGORITHM = "alg";
	const NAME_JWK_SET_URL = "jku";
	const NAME_JSON_WEB_KEY = "jwk";
	const NAME_KEY_ID = "kid";
	const NAME_X509_URL = "x5u";
	const NAME_X509_CERTIFICATE_CHAIN = "x5c";
	const NAME_X509_CERTIFICATE_SHA1_THUMBPRINT = "x5t";
	const NAME_X509_CERTIFICATE_SHA256_THUMBPRINT = "x5t#S256";
	const NAME_CRITICAL = "crit";
	const NAME_ENCRYPTION_ALGORITHM = "enc";
	const NAME_COMPRESSION_ALGORITHM = "zip";
}
