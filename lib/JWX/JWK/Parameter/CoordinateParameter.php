<?php

declare(strict_types = 1);

namespace Sop\JWX\JWK\Parameter;

use Sop\JWX\Util\Base64;

/**
 * Base class for EC coordinate parameters.
 */
abstract class CoordinateParameter extends JWKParameter
{
    /**
     * Get coordinate in octet string representation.
     */
    public function coordinateOctets(): string
    {
        return Base64::urlDecode($this->_value);
    }
}
