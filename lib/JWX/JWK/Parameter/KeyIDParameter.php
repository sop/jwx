<?php

declare(strict_types = 1);

namespace Sop\JWX\JWK\Parameter;

use Sop\JWX\Parameter\Feature\StringParameterValue;

/**
 * Implements 'Key ID' parameter.
 *
 * @see https://tools.ietf.org/html/rfc7517#section-4.5
 */
class KeyIDParameter extends JWKParameter
{
    use StringParameterValue;

    /**
     * Constructor.
     *
     * @param string $id Key ID
     */
    public function __construct(string $id)
    {
        parent::__construct(self::PARAM_KEY_ID, $id);
    }
}
