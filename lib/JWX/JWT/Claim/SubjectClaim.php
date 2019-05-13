<?php

declare(strict_types = 1);

namespace Sop\JWX\JWT\Claim;

use Sop\JWX\JWT\Claim\Validator\EqualsValidator;

/**
 * Implements 'Subject' claim.
 *
 * @see https://tools.ietf.org/html/rfc7519#section-4.1.2
 */
class SubjectClaim extends RegisteredClaim
{
    /**
     * Constructor.
     *
     * @param string $subject Subject
     */
    public function __construct(string $subject)
    {
        parent::__construct(self::NAME_SUBJECT, $subject, new EqualsValidator());
    }
}
