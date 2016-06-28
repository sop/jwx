<?php

namespace JWX\JWK\Parameter;

use JWX\Parameter\Feature\Base64URLValue;


/**
 * Implements 'X.509 Certificate SHA-1 Thumbprint' parameter.
 *
 * @link https://tools.ietf.org/html/rfc7517#section-4.8
 */
class X509CertificateSHA1ThumbprintParameter extends JWKParameter
{
	use Base64URLValue;
	
	/**
	 * Constructor
	 *
	 * @param string $thumbprint Base64url encoded SHA-1 hash
	 */
	public function __construct($thumbprint) {
		$this->_validateEncoding($thumbprint);
		parent::__construct(self::PARAM_X509_CERTIFICATE_SHA1_THUMBPRINT, 
			(string) $thumbprint);
	}
}
