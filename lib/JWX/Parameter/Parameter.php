<?php

namespace JWX\Parameter;

/**
 * Base class for JWT and JWK parameters.
 */
abstract class Parameter
{
    /**
     * Parameter name.
     *
     * @var string $_name
     */
    protected $_name;
    
    /**
     * Parameter value.
     *
     * @var mixed $_value
     */
    protected $_value;
    
    /**
     * Get the parameter name.
     *
     * @return string
     */
    public function name()
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
