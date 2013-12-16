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
		
		if (function_exists('hash_hmac')) {
			return hash_hmac('sha1', $value, SIGNER_SECRET);
		}
		else {
			// @codeCoverageIgnoreStart
			return self::hmac('sha1', $value, SIGNER_SECRET);
			// @codeCoverageIgnoreEnd
		}
	}
	
	/**
	 * Creates a signed (signature + encoded value) string.
	 * 
	 * @param	string	$value
	 * @return	string
	 */
	public static function createSignedString($value) {
		return self::getSignature($value).'-'.base64_encode($value);
	}
	
	/**
	 * Returns whether the given string is a proper signed string.
	 * (i.e. consists of a valid signature + encoded value)
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
	 * @param	string		$string
	 * @return	null|string
	 * @see		\wcf\util\Signer::validateSignedString()
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
	 *
	 * @codeCoverageIgnore
	 */
	public static function setSignedCookie($name, $value = '', $expire = 0) {
		HeaderUtil::setCookie($name, self::createSignedString($value), $expire);
	}
	
	/**
	 * Returns the value of the cookie with the given $name, after
	 * validating whether it is properly signed.
	 * 
	 * - Returns null if the cookie is not properly signed, or does not exist.
	 * - Unsets the cookie if it is not properly signed.
	 * 
	 * @param	string		$name
	 * @return	null|string
	 * @see		\wcf\util\Signer::getValueFromSignedString()
	 * 
	 * @codeCoverageIgnore
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
	
	/**
	 * HMAC function based on RFC 2104 <http://tools.ietf.org/html/rfc2104>
	 * This function mimics PHPs hash_hmac function
	 *
	 * @param	string	$algo		Name of hashing algorithm to be used
	 * @param	string	$data		Data to be hashed
	 * @param	string	$key		Encryption key
	 * @param	boolean	$rawOutput	Determines whether raw binary should be output
	 * @return	string			If $rawOutput is enabled, a binary string is being returned
	 */
	private static function hmac($algo, $data, $key, $rawOutput = false) {
		$algo = trim(strtolower($algo));
		
		switch ($algo) {
			case 'md5':
			case 'sha1':
				$blockSize = 64;
			break;
			default:
				throw new \wcf\system\exception\SystemException('Unknown hashing algorithm: ' . $algo);
		}
		
		if (strlen($key) > $blockSize) {
			$key = $algo($key, true);
		}
		
		$key = str_pad($key, $blockSize, "\x00", STR_PAD_RIGHT);
		
		$iKey = '';
		$oKey = '';
		for ($i = 0; $i < $blockSize; $i++) {
			$iKey .= $key[$i] ^ "\x36";
			$oKey .= $key[$i] ^ "\x5C";
		}
		
		return $algo($oKey . $algo($iKey . $data, true), $rawOutput);
	}
	
	/**
	 * @codeCoverageIgnore
	 */
	private function __construct() { }
}
