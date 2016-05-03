<?php

namespace JWX\JWT\Parameter;


/**
 * Implements 'X.509 Certificate Chain' parameter.
 *
 * @link https://tools.ietf.org/html/rfc7515#section-4.1.6
 */
class X509CertificateChainParameter extends RegisteredJWTParameter
{
	/**
	 * Constructor
	 *
	 * @param string ...$certs Base64 encoded DER certificate
	 */
	public function __construct(...$certs) {
		parent::__construct(self::PARAM_X509_CERTIFICATE_CHAIN, $certs);
	}
	
	public static function fromJSONValue($value) {
		if (!is_array($value)) {
			throw new \UnexpectedValueException("Array expected.");
		}
		return new static(...$value);
	}
}
