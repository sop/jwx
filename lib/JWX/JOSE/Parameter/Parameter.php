<?php

namespace JWX\JOSE\Parameter;


class Parameter
{
	protected $_name;
	
	protected $_value;
	
	public function __construct($name, $value) {
		$this->_name = $name;
		$this->_value = $value;
	}
	
	public static function fromNameAndValue($name, $value) {
		switch ($name) {
		case RegisteredParameter::NAME_TYPE:
			return new TypeParameter($value);
		case RegisteredParameter::NAME_CONTENT_TYPE:
			return new ContentTypeParameter($value);
		case RegisteredParameter::NAME_ALGORITHM:
			return new AlgorithmParameter($value);
		}
		return new Parameter($name, $value);
	}
	
	public function name() {
		return $this->_name;
	}
	
	public function value() {
		return $this->_value;
	}
}
