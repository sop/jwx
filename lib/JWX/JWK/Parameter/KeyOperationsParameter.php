<?php

namespace JWX\JWK\Parameter;


/**
 * Implements 'Key Operations' parameter.
 *
 * @link https://tools.ietf.org/html/rfc7517#section-4.3
 */
class KeyOperationsParameter extends RegisteredJWKParameter
{
	const OP_SIGN = "sign";
	const OP_VERIFY = "verify";
	const OP_ENCRYPT = "encrypt";
	const OP_DECRYPT = "decrypt";
	const OP_WRAP_KEY = "wrapKey";
	const OP_UNWRAP_KEY = "unwrapKey";
	const OP_DERIVE_KEY = "deriveKey";
	const OP_DERIVE_BITS = "deriveBits";
	
	/**
	 * Constructor
	 *
	 * @param string ...$ops Key operations
	 */
	public function __construct(...$ops) {
		parent::__construct(self::PARAM_KEY_OPERATIONS, $ops);
	}
	
	public static function fromJSONValue($value) {
		if (!is_array($value)) {
			throw new \UnexpectedValueException("key_ops must be an array.");
		}
		return new self(...$value);
	}
}
