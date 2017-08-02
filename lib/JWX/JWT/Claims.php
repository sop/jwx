<?php

namespace JWX\JWT;

use JWX\JWT\Claim\Claim;
use JWX\JWT\Claim\TypedClaims;

/**
 * Represents a set of Claim objects.
 *
 * @link https://tools.ietf.org/html/rfc7519#section-4
 */
class Claims implements \Countable, \IteratorAggregate
{
    use TypedClaims;
    
    /**
     * Claims.
     *
     * @var Claim[] $_claims
     */
    protected $_claims;
    
    /**
     * Constructor.
     *
     * @param Claim ...$claims Zero or more claims
     */
    public function __construct(Claim ...$claims)
    {
        $this->_claims = array();
        foreach ($claims as $claim) {
            $this->_claims[$claim->name()] = $claim;
        }
    }
    
    /**
     * Initialize from a JSON string.
     *
     * @param string $json JSON
     * @throws \UnexpectedValueException If JSON is malformed
     * @return self
     */
    public static function fromJSON($json)
    {
        $claims = array();
        $fields = json_decode($json, true, 32, JSON_BIGINT_AS_STRING);
        if (!is_array($fields)) {
            throw new \UnexpectedValueException("Invalid JSON.");
        }
        foreach ($fields as $name => $value) {
            $claims[] = Claim::fromNameAndValue($name, $value);
        }
        return new self(...$claims);
    }
    
    /**
     * Get self with Claim objects added.
     *
     * @param Claim ...$claims One or more Claim objects
     * @return self
     */
    public function withClaims(Claim ...$claims)
    {
        $obj = clone $this;
        foreach ($claims as $claim) {
            $obj->_claims[$claim->name()] = $claim;
        }
        return $obj;
    }
    
    /**
     * Get all claims.
     *
     * @return Claim[]
     */
    public function all()
    {
        return $this->_claims;
    }
    
    /**
     * Check whether claim is present.
     *
     * @param string $name Claim name
     * @return true
     */
    public function has($name)
    {
        return isset($this->_claims[$name]);
    }
    
    /**
     * Get claim by name.
     *
     * @param string $name Claim name
     * @throws \LogicException If claim is not present
     * @return Claim
     */
    public function get($name)
    {
        if (!isset($this->_claims[$name])) {
            throw new \LogicException("Claim $name not set.");
        }
        return $this->_claims[$name];
    }
    
    /**
     * Convert to a JSON.
     *
     * @return string
     */
    public function toJSON()
    {
        $data = array();
        foreach ($this->_claims as $claim) {
            $data[$claim->name()] = $claim->value();
        }
        return json_encode((object) $data, JSON_UNESCAPED_SLASHES);
    }
    
    /**
     * Check whether a claims set is valid in the given context.
     *
     * @param ValidationContext $ctx Validation context
     * @return bool
     */
    public function isValid(ValidationContext $ctx)
    {
        try {
            $ctx->validate($this);
        } catch (\RuntimeException $e) {
            return false;
        }
        return true;
    }
    
    /**
     * Get the number of claims.
     *
     * @see \Countable::count()
     * @return int
     */
    public function count()
    {
        return count($this->_claims);
    }
    
    /**
     * Get iterator for Claim objects keyed by claim name.
     *
     * @see \IteratorAggregate::getIterator()
     * @return \ArrayIterator
     */
    public function getIterator()
    {
        return new \ArrayIterator($this->_claims);
    }
    
    /**
     * Convert to string.
     *
     * @return string
     */
    public function __toString()
    {
        return $this->toJSON();
    }
}
