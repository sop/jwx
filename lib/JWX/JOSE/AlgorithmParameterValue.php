<?php

namespace JWX\JOSE;


interface AlgorithmParameterValue
{
	/**
	 * Get algorithm type as an 'alg' parameter value
	 *
	 * @return string
	 */
	public function algorithmParamValue();
}
