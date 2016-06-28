<?php

namespace JWX\JWK\Parameter;

use JWX\Parameter\Feature\StringParameterValue;


/**
 * Implements 'Curve' parameter.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-6.2.1.1
 */
class CurveParameter extends JWKParameter
{
	use StringParameterValue;
	
	/**
	 * P-256 Curve
	 *
	 * @var string
	 */
	const CURVE_P256 = "P-256";
	
	/**
	 * P-384 Curve
	 *
	 * @var string
	 */
	const CURVE_P384 = "P-384";
	
	/**
	 * P-521 Curve
	 *
	 * @var string
	 */
	const CURVE_P521 = "P-521";
	
	/**
	 * Mapping from curve OID to curve name.
	 *
	 * @internal
	 *
	 * @var array
	 */
	const MAP_OID_TO_CURVE = array(
		/* @formatter:off */
		"1.2.840.10045.3.1.7" => self::CURVE_P256,
		"1.3.132.0.34" => self::CURVE_P384,
		"1.3.132.0.35" => self::CURVE_P521
		/* @formatter:on */
	);
	
	/**
	 * Mapping from curve name to bit size.
	 *
	 * @internal
	 *
	 * @var array
	 */
	const MAP_CURVE_TO_SIZE = array(
		/* @formatter:off */
		self::CURVE_P256 => 256,
		self::CURVE_P384 => 384,
		self::CURVE_P521 => 521
		/* @formatter:on */
	);
	
	/**
	 * Constructor
	 *
	 * @param string $curve Curve name
	 */
	public function __construct($curve) {
		parent::__construct(self::PARAM_CURVE, $curve);
	}
	
	/**
	 * Initialize from curve OID.
	 *
	 * @param string $oid Object identifier in dotted format
	 * @throws \UnexpectedValueException If the curve is not supported
	 * @return self
	 */
	public static function fromOID($oid) {
		if (!array_key_exists($oid, self::MAP_OID_TO_CURVE)) {
			throw new \UnexpectedValueException("OID $oid not supported.");
		}
		$curve = self::MAP_OID_TO_CURVE[$oid];
		return new self($curve);
	}
	
	/**
	 * Get key size in bits for the curve.
	 *
	 * @throws \UnexpectedValueException
	 * @return int
	 */
	public function keySizeBits() {
		if (!array_key_exists($this->_value, self::MAP_CURVE_TO_SIZE)) {
			throw new \UnexpectedValueException(
				"Curve " . $this->_value . " not supported.");
		}
		return self::MAP_CURVE_TO_SIZE[$this->_value];
	}
	
	/**
	 * Get the curve OID by curve name.
	 *
	 * @param string $name Curve parameter name
	 * @throws \UnexpectedValueException If the curve is not supported
	 * @return string OID in dotted format
	 */
	public static function nameToOID($name) {
		static $reverseMap;
		if (!isset($reverseMap)) {
			$reverseMap = array_flip(self::MAP_OID_TO_CURVE);
		}
		if (!isset($reverseMap[$name])) {
			throw new \UnexpectedValueException("Curve $name not supported.");
		}
		return $reverseMap[$name];
	}
}
