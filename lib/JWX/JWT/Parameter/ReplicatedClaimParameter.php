<?php

declare(strict_types = 1);

namespace JWX\JWT\Parameter;

use JWX\JWT\Claim\Claim;

/**
 * Parameter allowing claims to be inserted into header.
 *
 * @link https://tools.ietf.org/html/rfc7519#section-5.3
 */
class ReplicatedClaimParameter extends JWTParameter
{
    /**
     * Constructor.
     *
     * @param Claim $claim
     */
    public function __construct(Claim $claim)
    {
        parent::__construct($claim->name(), $claim->value());
    }
}
