<?php

declare(strict_types = 1);

namespace JWX\JWK\Symmetric;

use JWX\JWK\JWK;
use JWX\JWK\Parameter\JWKParameter;
use JWX\JWK\Parameter\KeyTypeParameter;
use JWX\JWK\Parameter\KeyValueParameter;
use JWX\Util\Base64;

/**
 * JWK containing a symmetric key.
 *
 * @link http://tools.ietf.org/html/rfc7518#section-6.4
 */
class SymmetricKeyJWK extends JWK
{
    /**
     * Parameter names managed by this class.
     *
     * @internal
     *
     * @var string[]
     */
    const MANAGED_PARAMS = array(
        /* @formatter:off */
        JWKParameter::PARAM_KEY_TYPE, 
        JWKParameter::PARAM_KEY_VALUE
        /* @formatter:on */
    );
    
    /**
     * Constructor.
     *
     * @param JWKParameter ...$params
     * @throws \UnexpectedValueException If missing required parameter
     */
    public function __construct(JWKParameter ...$params)
    {
        parent::__construct(...$params);
        foreach (self::MANAGED_PARAMS as $name) {
            if (!$this->has($name)) {
                throw new \UnexpectedValueException("Missing '$name' parameter.");
            }
        }
        if ($this->keyTypeParameter()->value() != KeyTypeParameter::TYPE_OCT) {
            throw new \UnexpectedValueException("Invalid key type.");
        }
    }
    
    /**
     * Initialize from a key string.
     *
     * @param string $key Symmetric key
     * @param JWKParameter ...$params Optional additional parameters
     * @return self
     */
    public static function fromKey(string $key, JWKParameter ...$params): self
    {
        $params[] = new KeyTypeParameter(KeyTypeParameter::TYPE_OCT);
        $params[] = KeyValueParameter::fromString($key);
        return new self(...$params);
    }
    
    /**
     * Get the symmetric key.
     *
     * @return string
     */
    public function key(): string
    {
        return Base64::urlDecode($this->keyValueParameter()->value());
    }
}
