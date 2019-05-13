<?php

declare(strict_types = 1);

namespace Sop\JWX\JWK;

use Sop\JWX\JWK\Parameter\JWKParameter;

/**
 * Represents a JWK set structure.
 *
 * @see https://tools.ietf.org/html/rfc7517#section-5
 */
class JWKSet implements \Countable, \IteratorAggregate
{
    /**
     * JWK objects.
     *
     * @var JWK[]
     */
    protected $_jwks;

    /**
     * Additional members.
     *
     * @var array
     */
    protected $_additional;

    /**
     * JWK mappings.
     *
     * @var array
     */
    private $_mappings = [];

    /**
     * Constructor.
     *
     * @param JWK ...$jwks
     */
    public function __construct(JWK ...$jwks)
    {
        $this->_jwks = $jwks;
        $this->_additional = [];
    }

    /**
     * Reset internal cache variables on clone.
     */
    public function __clone()
    {
        $this->_mappings = [];
    }

    /**
     * Initialize from an array representing a JSON object.
     *
     * @param array $members
     *
     * @throws \UnexpectedValueException
     *
     * @return self
     */
    public static function fromArray(array $members): self
    {
        if (!isset($members['keys']) || !is_array($members['keys'])) {
            throw new \UnexpectedValueException(
                "JWK Set must have a 'keys' member.");
        }
        $jwks = array_map(
            function ($jwkdata) {
                return JWK::fromArray($jwkdata);
            }, $members['keys']);
        unset($members['keys']);
        $obj = new self(...$jwks);
        $obj->_additional = $members;
        return $obj;
    }

    /**
     * Initialize from a JSON string.
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
     * Get self with keys added.
     *
     * @param JWK ...$keys JWK objects
     *
     * @return self
     */
    public function withKeys(JWK ...$keys): self
    {
        $obj = clone $this;
        $obj->_jwks = array_merge($obj->_jwks, $keys);
        return $obj;
    }

    /**
     * Get all JWK's in a set.
     *
     * @return JWK[]
     */
    public function keys(): array
    {
        return $this->_jwks;
    }

    /**
     * Get the first JWK in the set.
     *
     * @throws \LogicException
     *
     * @return JWK
     */
    public function first(): JWK
    {
        if (!count($this->_jwks)) {
            throw new \LogicException('No keys.');
        }
        return $this->_jwks[0];
    }

    /**
     * Check whether set has a JWK with a given key ID.
     *
     * @param string $id
     *
     * @return bool
     */
    public function hasKeyID(string $id): bool
    {
        return null !== $this->_getKeyByID($id);
    }

    /**
     * Get a JWK by a key ID.
     *
     * @param string $id
     *
     * @throws \LogicException
     *
     * @return JWK
     */
    public function keyByID(string $id): JWK
    {
        $jwk = $this->_getKeyByID($id);
        if (!$jwk) {
            throw new \LogicException("No key ID {$id}.");
        }
        return $jwk;
    }

    /**
     * Convert to array.
     *
     * @return array
     */
    public function toArray(): array
    {
        $data = $this->_additional;
        $data['keys'] = array_map(
            function (JWK $jwk) {
                return $jwk->toArray();
            }, $this->_jwks);
        return $data;
    }

    /**
     * Convert to JSON.
     *
     * @return string
     */
    public function toJSON(): string
    {
        return json_encode((object) $this->toArray(), JSON_UNESCAPED_SLASHES);
    }

    /**
     * Get the number of keys.
     *
     * @see \Countable::count()
     */
    public function count(): int
    {
        return count($this->_jwks);
    }

    /**
     * Get iterator for JWK objects.
     *
     * @see \IteratorAggregate::getIterator()
     *
     * @return \ArrayIterator
     */
    public function getIterator(): \ArrayIterator
    {
        return new \ArrayIterator($this->_jwks);
    }

    /**
     * Get JWK by key ID.
     *
     * @param string $id
     *
     * @return null|JWK Null if not found
     */
    protected function _getKeyByID(string $id): ?JWK
    {
        $map = $this->_getMapping(JWKParameter::PARAM_KEY_ID);
        return isset($map[$id]) ? $map[$id] : null;
    }

    /**
     * Get mapping from parameter values of given parameter name to JWK.
     *
     * Later duplicate value shall override earlier JWK.
     *
     * @param string $name Parameter name
     *
     * @return array
     */
    protected function _getMapping(string $name): array
    {
        if (!isset($this->_mappings[$name])) {
            $mapping = [];
            foreach ($this->_jwks as $jwk) {
                if ($jwk->has($name)) {
                    $key = (string) $jwk->get($name)->value();
                    $mapping[$key] = $jwk;
                }
            }
            $this->_mappings[$name] = $mapping;
        }
        return $this->_mappings[$name];
    }
}
