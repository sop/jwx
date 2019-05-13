<?php

declare(strict_types = 1);

namespace Sop\JWX\JWT\Parameter;

use Sop\JWX\Parameter\Parameter;

/**
 * Implements 'PBES2 Count' parameter.
 *
 * @see https://tools.ietf.org/html/rfc7518#section-4.8.1.2
 */
class PBES2CountParameter extends JWTParameter
{
    /**
     * Constructor.
     *
     * @param int $count
     */
    public function __construct(int $count)
    {
        parent::__construct(self::PARAM_PBES2_COUNT, $count);
    }

    /**
     * Initialize from a JSON value.
     *
     * @param int $value
     *
     * @return self
     */
    public static function fromJSONValue($value): Parameter
    {
        return new self(intval($value));
    }
}
