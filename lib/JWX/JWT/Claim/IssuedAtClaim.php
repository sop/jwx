<?php

declare(strict_types = 1);

namespace Sop\JWX\JWT\Claim;

use Sop\JWX\JWT\Claim\Feature\NumericDateClaim;

/**
 * Implements 'Issued At' claim.
 *
 * @see https://tools.ietf.org/html/rfc7519#section-4.1.6
 */
class IssuedAtClaim extends RegisteredClaim
{
    use NumericDateClaim;

    /**
     * Constructor.
     *
     * @param int $issue_time Issued at time as a unix timestamp
     */
    public function __construct(int $issue_time)
    {
        parent::__construct(self::NAME_ISSUED_AT, $issue_time);
    }

    /**
     * Initialize with time set to current time.
     */
    public static function now(): self
    {
        return new self(time());
    }
}
