<?php

declare(strict_types = 1);

namespace Sop\JWX\JWT\Parameter;

use Sop\JWX\Parameter\Feature\StringParameterValue;

/**
 * Implements 'Key ID' parameter.
 *
 * @see https://tools.ietf.org/html/rfc7515#section-4.1.4
 */
class KeyIDParameter extends JWTParameter
{
    use StringParameterValue;

    /**
     * Constructor.
     *
     * @param string $id
     */
    public function __construct(string $id)
    {
        parent::__construct(self::PARAM_KEY_ID, $id);
    }
}
