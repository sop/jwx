<?php

namespace JWX\JWT\Claim\Feature;


/**
 * Trait for claims having NumericDate value.
 */
trait NumericDateClaim
{
	/**
	 * Initialize instance from date/time string
	 *
	 * @param string $time
	 * @return static
	 */
	public static function fromString($time) {
		$dt = new \DateTimeImmutable($time, new \DateTimeZone("UTC"));
		return new static($dt->getTimestamp());
	}
	
	/**
	 * Get date as a unix timestamp
	 *
	 * @return int
	 */
	public function timestamp() {
		return (int)$this->_value;
	}
	
	/**
	 * Get date as a datetime object
	 *
	 * @return \DateTimeImmutable
	 */
	public function dateTime() {
		return \DateTimeImmutable::createFromFormat("!U", $this->_value, 
			new \DateTimeZone("UTC"));
	}
}
