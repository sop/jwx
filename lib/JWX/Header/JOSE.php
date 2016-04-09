<?php

namespace JWX\Header;

use JWX\Header\Parameter\Parameter;


class JOSE extends Header
{
	/**
	 * Constructor
	 *
	 * @param Header ...$headers One or more headers to merge
	 */
	public function __construct(Header ...$headers) {
		$params = array();
		foreach ($headers as $header) {
			foreach ($header->parameters() as $param) {
				if (isset($params[$param->name()])) {
					throw new \UnexpectedValueException("Duplicate parameter");
				}
				$params[$param->name()] = $param;
			}
		}
		parent::__construct(...array_values($params));
	}
}
