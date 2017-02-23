<?php

define("TEST_ASSETS_DIR", __DIR__ . "/assets");
define("COOKBOOK_DIR", dirname(__DIR__) . "/vendor/ietf-jose/cookbook");
require dirname(__DIR__) . "/vendor/autoload.php";
// set default timezone
if (empty(ini_get("date.timezone"))) {
	ini_set("date.timezone", "UTC");
}
// backwards compatibility on PHPUnit 6
if (!class_exists("PHPUnit_Framework_TestCase")) {
	class_alias("PHPUnit\Framework\TestCase", "PHPUnit_Framework_TestCase");
}
