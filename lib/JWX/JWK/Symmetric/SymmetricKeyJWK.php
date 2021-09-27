<?php

declare(strict_types = 1);

namespace Sop\JWX\JWK\Symmetric;

use Sop\JWX\JWK\JWK;
use Sop\JWX\JWK\Parameter\JWKParameter;
use Sop\JWX\JWK\Parameter\KeyTypeParameter;
use Sop\JWX\JWK\Parameter\KeyValueParameter;
use Sop\JWX\Util\Base64;

/**
 * JWK containing a symmetric key.
 *
 * @see http://tools.ietf.org/html/rfc7518#section-6.4
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
    public const MANAGED_PARAMS = [
        JWKParameter::PARAM_KEY_TYPE,
        JWKParameter::PARAM_KEY_VALUE,
    ];

    /**
     * Constructor.
     *
     * @param JWKParameter ...$params
     *
     * @throws \UnexpectedValueException If missing required parameter
     */
    public function __construct(JWKParameter ...$params)
    {
        parent::__construct(...$params);
        foreach (self::MANAGED_PARAMS as $name) {
            if (!$this->has($name)) {
                throw new \UnexpectedValueException(
                    "Missing '{$name}' parameter.");
            }
        }
        if (KeyTypeParameter::TYPE_OCT !== $this->keyTypeParameter()->value()) {
            throw new \UnexpectedValueException('Invalid key type.');
        }
    }

    /**
     * Initialize from a key string.
     *
     * @param string       $key       Symmetric key
     * @param JWKParameter ...$params Optional additional parameters
     */
    public static function fromKey(string $key, JWKParameter ...$params): self
    {
        $params[] = new KeyTypeParameter(KeyTypeParameter::TYPE_OCT);
        $params[] = KeyValueParameter::fromString($key);
        return new self(...$params);
    }

    /**
     * Get the symmetric key.
     */
    public function key(): string
    {
        return Base64::urlDecode($this->keyValueParameter()->value());
    }
}
