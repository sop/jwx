<?php

namespace JWX\JWT\Parameter;


class TypeParameter extends RegisteredJWTParameter
{
	public function __construct($value) {
		parent::__construct(self::PARAM_TYPE, $value);
	}
}
