<?php

declare(strict_types = 1);

namespace Sop\JWX\Parameter;

/**
 * Base class for JWT and JWK parameters.
 */
abstract class Parameter
{
    /**
     * Parameter name.
     *
     * @var string
     */
    protected $_name;

    /**
     * Parameter value.
     *
     * @var mixed
     */
    protected $_value;

    /**
     * Get the parameter name.
     *
     * @return string
     */
    public function name(): string
    {
        return $this->_name;
    }

    /**
     * Get the parameter value.
     *
     * @return mixed
     */
    public function value()
    {
        return $this->_value;
    }
}
