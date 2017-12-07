<?php

declare(strict_types = 1);

namespace JWX\JWT\Claim;

use JWX\JWT\Claim\Feature\NumericDateClaim;

/**
 * Implements 'Issued At' claim.
 *
 * @link https://tools.ietf.org/html/rfc7519#section-4.1.6
 */
class IssuedAtClaim extends RegisteredClaim
{
    use NumericDateClaim;
    
    /**
     * Constructor.
     *
     * @param int $issue_time Issued at time
     */
    public function __construct(int $issue_time)
    {
        parent::__construct(self::NAME_ISSUED_AT, $issue_time);
    }
    
    /**
     * Initialize with time set to current time
     *
     * @return self
     */
    public static function now(): self
    {
        return new self(time());
    }
}
