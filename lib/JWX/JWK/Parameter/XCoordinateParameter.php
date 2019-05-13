<?php

declare(strict_types = 1);

namespace Sop\JWX\JWK\Parameter;

use Sop\JWX\Parameter\Feature\Base64URLValue;

/**
 * Implements 'X Coordinate' parameter.
 *
 * @see https://tools.ietf.org/html/rfc7518#section-6.2.1.2
 */
class XCoordinateParameter extends CoordinateParameter
{
    use Base64URLValue;

    /**
     * Constructor.
     *
     * @param string $coord X coordinate in base64url encoding
     */
    public function __construct(string $coord)
    {
        $this->_validateEncoding($coord);
        parent::__construct(self::PARAM_X_COORDINATE, $coord);
    }
}
