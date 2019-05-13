<?php

declare(strict_types = 1);

namespace Sop\JWX\JWT\Claim;

use Sop\JWX\JWT\Claim\Validator\EqualsValidator;

/**
 * Implements 'JWT ID' claim.
 *
 * @see https://tools.ietf.org/html/rfc7519#section-4.1.7
 */
class JWTIDClaim extends RegisteredClaim
{
    /**
     * Constructor.
     *
     * @param string $id JWT unique identifier
     */
    public function __construct(string $id)
    {
        parent::__construct(self::NAME_JWT_ID, $id, new EqualsValidator());
    }
}
