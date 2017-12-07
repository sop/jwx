<?php

declare(strict_types = 1);

namespace JWX\JWK\Parameter;

use JWX\Util\Base64;

/**
 * Base class for EC coordinate parameters.
 */
abstract class CoordinateParameter extends JWKParameter
{
    /**
     * Get coordinate in octet string representation.
     *
     * @return string
     */
    public function coordinateOctets(): string
    {
        return Base64::urlDecode($this->_value);
    }
}
