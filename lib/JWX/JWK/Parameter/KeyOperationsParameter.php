<?php

namespace JWX\JWK\Parameter;


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
		return new self(...$value);
	}
}
