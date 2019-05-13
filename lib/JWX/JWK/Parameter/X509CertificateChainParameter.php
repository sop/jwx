<?php

declare(strict_types = 1);

namespace Sop\JWX\JWK\Parameter;

use Sop\JWX\Parameter\Feature\ArrayParameterValue;
use Sop\JWX\Util\Base64;

/**
 * Implements 'X.509 Certificate Chain' parameter.
 *
 * @see https://tools.ietf.org/html/rfc7517#section-4.7
 */
class X509CertificateChainParameter extends JWKParameter
{
    use ArrayParameterValue;

    /**
     * Constructor.
     *
     * @param string ...$certs Base64 encoded DER certificates
     */
    public function __construct(string ...$certs)
    {
        foreach ($certs as $cert) {
            if (!Base64::isValid($cert)) {
                throw new \UnexpectedValueException(
                    'Certificate must be base64 encoded.');
            }
        }
        parent::__construct(self::PARAM_X509_CERTIFICATE_CHAIN, $certs);
    }
}
