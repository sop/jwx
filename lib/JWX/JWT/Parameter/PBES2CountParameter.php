<?php

namespace JWX\JWT\Parameter;

/**
 * Implements 'PBES2 Count' parameter.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-4.8.1.2
 */
class PBES2CountParameter extends JWTParameter
{
    /**
     * Constructor.
     *
     * @param int $count
     */
    public function __construct($count)
    {
        parent::__construct(self::PARAM_PBES2_COUNT, intval($count));
    }
    
    /**
     * Initialize from a JSON value.
     *
     * @param int $value
     * @return self
     */
    public static function fromJSONValue($value)
    {
        return new self(intval($value));
    }
}
