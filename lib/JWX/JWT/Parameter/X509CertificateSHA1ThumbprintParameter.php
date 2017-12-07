<?php

declare(strict_types = 1);

namespace JWX\JWT\Parameter;

use JWX\Parameter\Feature\Base64URLValue;

/**
 * Implements 'X.509 Certificate SHA-1 Thumbprint' parameter.
 *
 * @link https://tools.ietf.org/html/rfc7515#section-4.1.7
 */
class X509CertificateSHA1ThumbprintParameter extends JWTParameter
{
    use Base64URLValue;
    
    /**
     * Constructor.
     *
     * @param string $thumbprint Base64url encoded SHA-1 hash
     */
    public function __construct(string $thumbprint)
    {
        $this->_validateEncoding($thumbprint);
        parent::__construct(self::PARAM_X509_CERTIFICATE_SHA1_THUMBPRINT,
            $thumbprint);
    }
}
