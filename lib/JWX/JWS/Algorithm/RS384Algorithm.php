<?php

namespace JWX\JWS\Algorithm;


class RS384Algorithm extends RSAPKCS1Algorithm
{
	protected function _mdMethod() {
		return "sha384WithRSAEncryption";
	}
	
	public function algorithmParamValue() {
		return "RS384";
	}
}
