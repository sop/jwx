<?php

declare(strict_types = 1);

namespace Sop\JWX\JWT\Header;

use Sop\JWX\JWT\Parameter\JWTParameter;

/**
 * Represents a header used in JWS and JWE.
 */
class Header implements \Countable, \IteratorAggregate
{
    use TypedHeader;

    /**
     * Parameters.
     *
     * @var JWTParameter[]
     */
    protected $_parameters;

    /**
     * Constructor.
     *
     * @param JWTParameter ...$params Parameters
     */
    public function __construct(JWTParameter ...$params)
    {
        $this->_parameters = [];
        foreach ($params as $param) {
            $this->_parameters[$param->name()] = $param;
        }
    }

    /**
     * Initialize from an array representing a JSON object.
     *
     * @param array $members
     *
     * @return self
     */
    public static function fromArray(array $members): self
    {
        $params = [];
        foreach ($members as $name => $value) {
            $params[] = JWTParameter::fromNameAndValue($name, $value);
        }
        return new self(...$params);
    }

    /**
     * Initialize from a JSON.
     *
     * @param string $json
     *
     * @throws \UnexpectedValueException
     *
     * @return self
     */
    public static function fromJSON(string $json): self
    {
        $members = json_decode($json, true, 32, JSON_BIGINT_AS_STRING);
        if (!is_array($members)) {
            throw new \UnexpectedValueException('Invalid JSON.');
        }
        return self::fromArray($members);
    }

    /**
     * Get self with parameters added.
     *
     * @param JWTParameter ...$param
     *
     * @return self
     */
    public function withParameters(JWTParameter ...$params): self
    {
        $obj = clone $this;
        foreach ($params as $param) {
            $obj->_parameters[$param->name()] = $param;
        }
        return $obj;
    }

    /**
     * Get all parameters.
     *
     * @return JWTParameter[]
     */
    public function parameters(): array
    {
        return $this->_parameters;
    }

    /**
     * Whether parameters are present.
     *
     * Returns false if any of the given parameters is not set.
     *
     * @param string ...$names Parameter names
     *
     * @return bool
     */
    public function has(string ...$names): bool
    {
        foreach ($names as $name) {
            if (!isset($this->_parameters[$name])) {
                return false;
            }
        }
        return true;
    }

    /**
     * Get a parameter.
     *
     * @param string $name Parameter name
     *
     * @throws \LogicException
     *
     * @return JWTParameter
     */
    public function get(string $name): JWTParameter
    {
        if (!$this->has($name)) {
            throw new \LogicException("Parameter {$name} doesn't exists.");
        }
        return $this->_parameters[$name];
    }

    /**
     * Convert to a JSON.
     *
     * @return string
     */
    public function toJSON(): string
    {
        if (empty($this->_parameters)) {
            return '';
        }
        $data = [];
        foreach ($this->_parameters as $param) {
            $data[$param->name()] = $param->value();
        }
        return json_encode((object) $data, JSON_UNESCAPED_SLASHES);
    }

    /**
     * Get the number of parameters.
     *
     * @see \Countable::count()
     *
     * @return int
     */
    public function count(): int
    {
        return count($this->_parameters);
    }

    /**
     * Get iterator for the parameters.
     *
     * @see \IteratorAggregate::getIterator()
     *
     * @return \ArrayIterator
     */
    public function getIterator(): \ArrayIterator
    {
        return new \ArrayIterator($this->_parameters);
    }
}
