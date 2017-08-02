<?php

namespace JWX\JWT\Claim;

use JWX\JWT\Claim\Feature\NumericDateClaim;
use JWX\JWT\Claim\Feature\ReferenceTimeValidation;
use JWX\JWT\Claim\Validator\LessOrEqualValidator;

/**
 * Implements 'Not Before' claim.
 *
 * @link https://tools.ietf.org/html/rfc7519#section-4.1.5
 */
class NotBeforeClaim extends RegisteredClaim
{
    use NumericDateClaim;
    use ReferenceTimeValidation;
    
    /**
     * Constructor.
     *
     * @param int $not_before Not before time
     */
    public function __construct($not_before)
    {
        // validate that claim is before or at the constraint (reference time)
        parent::__construct(self::NAME_NOT_BEFORE, intval($not_before),
            new LessOrEqualValidator());
    }
    
    /**
     * Initialize with time set to current time
     *
     * @return self
     */
    public static function now()
    {
        return new self(time());
    }
}
