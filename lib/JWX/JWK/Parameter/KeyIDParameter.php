<?php

namespace JWX\JWK\Parameter;


class KeyIDParameter extends RegisteredJWKParameter
{
	/**
	 * Constructor
	 *
	 * @param string $algo Key ID
	 */
	public function __construct($id) {
		parent::__construct(self::PARAM_KEY_ID, $id);
	}
}
