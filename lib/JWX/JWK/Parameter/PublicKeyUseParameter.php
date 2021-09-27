<?php

declare(strict_types = 1);

namespace Sop\JWX\JWK\Parameter;

use Sop\JWX\Parameter\Feature\StringParameterValue;

/**
 * Implements 'Public Key Use' parameter.
 *
 * @see https://tools.ietf.org/html/rfc7517#section-4.2
 */
class PublicKeyUseParameter extends JWKParameter
{
    use StringParameterValue;

    public const USE_SIGNATURE = 'sig';
    public const USE_ENCRYPTION = 'enc';

    /**
     * Constructor.
     *
     * @param string $use Intended use of the public key
     */
    public function __construct(string $use)
    {
        parent::__construct(self::PARAM_PUBLIC_KEY_USE, $use);
    }
}
