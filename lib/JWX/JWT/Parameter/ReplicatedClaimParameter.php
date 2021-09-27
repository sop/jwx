<?php

declare(strict_types = 1);

namespace Sop\JWX\JWT\Parameter;

use Sop\JWX\JWT\Claim\Claim;

/**
 * Parameter allowing claims to be inserted into header.
 *
 * @see https://tools.ietf.org/html/rfc7519#section-5.3
 */
class ReplicatedClaimParameter extends JWTParameter
{
    /**
     * Constructor.
     */
    public function __construct(Claim $claim)
    {
        parent::__construct($claim->name(), $claim->value());
    }
}
