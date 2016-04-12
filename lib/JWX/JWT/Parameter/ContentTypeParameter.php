<?php

namespace JWX\JWT\Parameter;


class ContentTypeParameter extends RegisteredJWTParameter
{
	public function __construct($value) {
		parent::__construct(self::PARAM_CONTENT_TYPE, $value);
	}
}
