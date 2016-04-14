<?php

namespace JWX\JWT\Parameter;


class TypeParameter extends RegisteredJWTParameter
{
	public function __construct($type) {
		parent::__construct(self::PARAM_TYPE, $type);
	}
}
