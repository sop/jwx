<?php

namespace JWX\JWT\Claim;

use JWX\JWT\Claim\Validator\EqualsValidator;

/**
 * Implements 'Issuer' claim.
 *
 * @link https://tools.ietf.org/html/rfc7519#section-4.1.1
 */
class IssuerClaim extends RegisteredClaim
{
    /**
     * Constructor.
     *
     * @param string $issuer
     */
    public function __construct($issuer)
    {
        parent::__construct(self::NAME_ISSUER, (string) $issuer,
            new EqualsValidator());
    }
}
