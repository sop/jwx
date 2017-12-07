<?php

declare(strict_types = 1);

namespace JWX\JWT\Claim;

use JWX\JWT\Claim\Validator\ContainsValidator;

/**
 * Implements 'Audience' claim.
 *
 * @link https://tools.ietf.org/html/rfc7519#section-4.1.3
 */
class AudienceClaim extends RegisteredClaim
{
    /**
     * Constructor.
     *
     * @param string ...$audiences One or more audiences
     */
    public function __construct(string ...$audiences)
    {
        parent::__construct(self::NAME_AUDIENCE, $audiences,
            new ContainsValidator());
    }
    
    /**
     *
     * {@inheritdoc}
     */
    public static function fromJSONValue($value): self
    {
        $value = (array) $value;
        return new self(...$value);
    }
}
