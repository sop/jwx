<?php

declare(strict_types = 1);

namespace Sop\JWX\JWT\Claim;

use Sop\JWX\JWT\Claim\Validator\EqualsValidator;

/**
 * Implements 'Issuer' claim.
 *
 * @see https://tools.ietf.org/html/rfc7519#section-4.1.1
 */
class IssuerClaim extends RegisteredClaim
{
    /**
     * Constructor.
     *
     * @param string $issuer
     */
    public function __construct(string $issuer)
    {
        parent::__construct(self::NAME_ISSUER, $issuer, new EqualsValidator());
    }
}
