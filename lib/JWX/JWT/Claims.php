<?php

declare(strict_types = 1);

namespace Sop\JWX\JWT;

use Sop\JWX\JWT\Claim\Claim;
use Sop\JWX\JWT\Claim\TypedClaims;

/**
 * Represents a set of Claim objects.
 *
 * @see https://tools.ietf.org/html/rfc7519#section-4
 */
class Claims implements \Countable, \IteratorAggregate
{
    use TypedClaims;

    /**
     * Claims.
     *
     * @var Claim[]
     */
    protected $_claims;

    /**
     * Constructor.
     *
     * @param Claim ...$claims Zero or more claims
     */
    public function __construct(Claim ...$claims)
    {
        $this->_claims = [];
        foreach ($claims as $claim) {
            $this->_claims[$claim->name()] = $claim;
        }
    }

    /**
     * Convert to string.
     *
     * @return string
     */
    public function __toString(): string
    {
        return $this->toJSON();
    }

    /**
     * Initialize from a JSON string.
     *
     * @param string $json JSON
     *
     * @throws \UnexpectedValueException If JSON is malformed
     *
     * @return self
     */
    public static function fromJSON(string $json): self
    {
        $claims = [];
        $fields = json_decode($json, true, 32, JSON_BIGINT_AS_STRING);
        if (!is_array($fields)) {
            throw new \UnexpectedValueException('Invalid JSON.');
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
     *
     * @return self
     */
    public function withClaims(Claim ...$claims): self
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
    public function all(): array
    {
        return $this->_claims;
    }

    /**
     * Check whether claim is present.
     *
     * @param string $name Claim name
     *
     * @return bool
     */
    public function has(string $name): bool
    {
        return isset($this->_claims[$name]);
    }

    /**
     * Get claim by name.
     *
     * @param string $name Claim name
     *
     * @throws \LogicException If claim is not present
     *
     * @return Claim
     */
    public function get(string $name): Claim
    {
        if (!isset($this->_claims[$name])) {
            throw new \LogicException("Claim {$name} not set.");
        }
        return $this->_claims[$name];
    }

    /**
     * Convert to a JSON.
     *
     * @return string
     */
    public function toJSON(): string
    {
        $data = [];
        foreach ($this->_claims as $claim) {
            $data[$claim->name()] = $claim->value();
        }
        return json_encode((object) $data, JSON_UNESCAPED_SLASHES);
    }

    /**
     * Check whether a claims set is valid in the given context.
     *
     * @param ValidationContext $ctx Validation context
     *
     * @return bool
     */
    public function isValid(ValidationContext $ctx): bool
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
     *
     * @return int
     */
    public function count(): int
    {
        return count($this->_claims);
    }

    /**
     * Get iterator for Claim objects keyed by claim name.
     *
     * @see \IteratorAggregate::getIterator()
     *
     * @return \ArrayIterator
     */
    public function getIterator(): \ArrayIterator
    {
        return new \ArrayIterator($this->_claims);
    }
}
