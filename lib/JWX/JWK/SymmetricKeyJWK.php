<?php

namespace JWX\JWK;

use JWX\JWK\Parameter\JWKParameter;
use JWX\JWK\Parameter\KeyTypeParameter;
use JWX\JWK\Parameter\RegisteredJWKParameter;
use JWX\Util\Base64;


class SymmetricKeyJWK extends JWK
{
	/**
	 * Parameter names managed by this class
	 *
	 * @var string[]
	 */
	private static $_managedParams = array(
		RegisteredJWKParameter::PARAM_KEY_TYPE, 
		RegisteredJWKParameter::PARAM_KEY_VALUE);
	
	/**
	 * Constructor
	 *
	 * @param JWKParameter ...$params
	 * @throws \UnexpectedValueException If missing required parameter
	 */
	public function __construct(JWKParameter ...$params) {
		parent::__construct(...$params);
		foreach (self::$_managedParams as $name) {
			if (!$this->has($name)) {
				throw new \UnexpectedValueException("Missing '$name' parameter");
			}
		}
		if ($this->get(RegisteredJWKParameter::PARAM_KEY_TYPE)->value() !=
			 KeyTypeParameter::TYPE_OCT) {
			throw new \UnexpectedValueException("Invalid key type");
		}
	}
	
	/**
	 * Get symmetric key
	 *
	 * @return string
	 */
	public function key() {
		$value = $this->get(RegisteredJWKParameter::PARAM_KEY_VALUE)->value();
		return Base64::urlDecode($value);
	}
}
