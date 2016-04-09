<?php

namespace JWX\Header\Parameter;


class ContentTypeParameter extends RegisteredParameter
{
	public function __construct($value) {
		parent::__construct(self::NAME_CONTENT_TYPE, $value);
	}
}
