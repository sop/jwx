<?php

use JWX\JWT\JOSE;
use JWX\JWT\Header;
use JWX\JWT\Parameter\TypeParameter;
use JWX\JWT\Parameter\ContentTypeParameter;
use JWX\JWT\Parameter\RegisteredParameter;


/**
 * @group header
 */
class JOSETest extends PHPUnit_Framework_TestCase
{
	public function testCreate() {
		$header = new Header(new TypeParameter("test"));
		$jose = new JOSE($header);
		$this->assertTrue($jose->has(RegisteredParameter::NAME_TYPE));
	}
	
	public function testMerge() {
		$h1 = new Header(new TypeParameter("test"));
		$h2 = new Header(new ContentTypeParameter("test"));
		$jose = new JOSE($h1, $h2);
		$this->assertCount(2, $jose);
	}
	
	/**
	 * @expectedException RuntimeException
	 */
	public function testDuplicateFail() {
		$h1 = new Header(new TypeParameter("test1"));
		$h2 = new Header(new TypeParameter("test2"));
		$jose = new JOSE($h1, $h2);
	}
}
