<?php

namespace JWX\JWT\Claim;

use JWX\JWT\Claim\Validator\EqualsValidator;

/**
 * Implements 'Subject' claim.
 *
 * @link https://tools.ietf.org/html/rfc7519#section-4.1.2
 */
class SubjectClaim extends RegisteredClaim
{
    /**
     * Constructor.
     *
     * @param string $subject Subject
     */
    public function __construct($subject)
    {
        parent::__construct(self::NAME_SUBJECT, (string) $subject,
            new EqualsValidator());
    }
}
