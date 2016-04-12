<?php

namespace JWX\JWT\Parameter;


class TypeParameter extends RegisteredParameter
{
	public function __construct($value) {
		parent::__construct(self::NAME_TYPE, $value);
	}
}
