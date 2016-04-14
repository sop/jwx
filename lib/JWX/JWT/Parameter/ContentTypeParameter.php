<?php

namespace JWX\JWT\Parameter;


class ContentTypeParameter extends RegisteredJWTParameter
{
	public function __construct($type) {
		parent::__construct(self::PARAM_CONTENT_TYPE, $type);
	}
}
