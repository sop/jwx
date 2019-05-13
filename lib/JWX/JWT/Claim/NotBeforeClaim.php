<?php

declare(strict_types = 1);

namespace Sop\JWX\JWT\Claim;

use Sop\JWX\JWT\Claim\Feature\NumericDateClaim;
use Sop\JWX\JWT\Claim\Feature\ReferenceTimeValidation;
use Sop\JWX\JWT\Claim\Validator\LessOrEqualValidator;

/**
 * Implements 'Not Before' claim.
 *
 * @see https://tools.ietf.org/html/rfc7519#section-4.1.5
 */
class NotBeforeClaim extends RegisteredClaim
{
    use NumericDateClaim;
    use ReferenceTimeValidation;

    /**
     * Constructor.
     *
     * @param int $not_before Not before time as a unix timestamp
     */
    public function __construct(int $not_before)
    {
        // validate that claim is before or at the constraint (reference time)
        parent::__construct(self::NAME_NOT_BEFORE, $not_before,
            new LessOrEqualValidator());
    }

    /**
     * Initialize with time set to current time.
     *
     * @return self
     */
    public static function now(): self
    {
        return new self(time());
    }
}
