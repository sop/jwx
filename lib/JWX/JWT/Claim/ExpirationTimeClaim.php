<?php

declare(strict_types = 1);

namespace Sop\JWX\JWT\Claim;

use Sop\JWX\JWT\Claim\Feature\NumericDateClaim;
use Sop\JWX\JWT\Claim\Feature\ReferenceTimeValidation;
use Sop\JWX\JWT\Claim\Validator\GreaterValidator;

/**
 * Implements 'Expiration Time' claim.
 *
 * @see https://tools.ietf.org/html/rfc7519#section-4.1.4
 */
class ExpirationTimeClaim extends RegisteredClaim
{
    use NumericDateClaim;
    use ReferenceTimeValidation;

    /**
     * Constructor.
     *
     * @param int $exp_time Expiration time as a unix timestamp
     */
    public function __construct(int $exp_time)
    {
        // validate that claim is after the constraint (reference time)
        parent::__construct(self::NAME_EXPIRATION_TIME, $exp_time,
            new GreaterValidator());
    }
}
