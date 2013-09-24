<?php
namespace wcf\util;

/**
 * Signs data with the WCF secret.
 * 
 * @author 	Tim Düsterhus
 * @copyright	2013 Tim Düsterhus
 * @license	BSD 3-Clause License <http://opensource.org/licenses/BSD-3-Clause>
 * @package	be.bastelstu.wcf.sso
 * @subpackage	action
 */
final class Signer {
	/**
	 * Signs the given value with the WCF secret.
	 * 
	 * @param	string	$value
	 * @return	string
	 */
	public static function getSignature($value) {
		if (SIGNER_SECRET === '') throw new \wcf\system\exception\SystemException('Empty SIGNER_SECRET, aborting');
		
		return hash_hmac('sha1', $value, SIGNER_SECRET);
	}
	
	/**
	 * Creates a signed string.
	 * 
	 * @param	string	$value
	 * @return	string
	 */
	public static function createSignedString($value) {
		return self::getSignature($value).'-'.base64_encode($value);
	}
	
	/**
	 * Returns whether the given string is properly signed.
	 * 
	 * @param	string	$string
	 * @return	boolean
	 */
	public static function validateSignedString($string) {
		$parts = explode('-', $string, 2);
		if (count($parts) !== 2) return false;
		list($signature, $value) = $parts;
		$value = base64_decode($value);
		
		return PasswordUtil::secureCompare($signature, self::getSignature($value));
	}
	
	/**
	 * Returns the value of a signed string, after
	 * validating whether it is properly signed.
	 * 
	 * - Returns null if the string is not properly signed.
	 * 
	 * @param	string	$string
	 * @return	null
	 */
	public static function getValueFromSignedString($string) {
		if (!self::validateSignedString($string)) return null;
		
		$parts = explode('-', $string, 2);
		return base64_decode($parts[1]);
	}
	
	/**
	 * Sets a signed cookie.
	 * 
	 * @see		\wcf\util\HeaderUtil
	 */
	public static function setSignedCookie($name, $value = '', $expire = 0) {
		HeaderUtil::setCookie($name, self::createSignedString($value), $expire);
	}
	
	/**
	 * Returns the value of the cookie with the given name, after
	 * validating whether it is properly signed.
	 * 
	 * - Returns null if the cookie is not properly signed, or does not exist.
	 * - Unsets the cookie if it is not properly signed.
	 * 
	 * @param	string	$name
	 * @return	string
	 */
	public static function getSignedCookie($name) {
		if (!isset($_COOKIE[COOKIE_PREFIX.$name])) return null;
		$value = self::getValueFromSignedString($_COOKIE[COOKIE_PREFIX.$name]);
		
		if ($value === null) {
			unset($_COOKIE[COOKIE_PREFIX.$name]);
			HeaderUtil::setCookie($name, '', -1337);
		}
		
		return $value;
	}
	
	private function __construct() { }
}
