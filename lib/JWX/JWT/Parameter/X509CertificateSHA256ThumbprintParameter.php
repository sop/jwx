<?php

namespace JWX\JWT\Parameter;


/**
 * Implements 'X.509 Certificate SHA-256 Thumbprint' parameter.
 *
 * @link https://tools.ietf.org/html/rfc7515#section-4.1.8
 */
class X509CertificateSHA256ThumbprintParameter extends RegisteredJWTParameter
{
	/**
	 * Constructor
	 *
	 * @param string $thumbprint Base64url encoded SHA-256 hash
	 */
	public function __construct($thumbprint) {
		parent::__construct(self::PARAM_X509_CERTIFICATE_SHA256_THUMBPRINT, 
			(string) $thumbprint);
	}
}
