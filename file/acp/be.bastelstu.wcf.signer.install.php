<?php
namespace be\bastelstu\wcf\signer;

/**
 * Generates a random key.
 *
 * @author 	Tim Düsterhus
 * @copyright	2010-2013 Tim Düsterhus
 * @license	BSD 3-Clause License <http://opensource.org/licenses/BSD-3-Clause>
 * @package	be.bastelstu.wcf.signer
 */
// @codingStandardsIgnoreFile
final class Installation {
	private $optionID;
	public function __construct($packageID) {
		$sql = "SELECT
				optionID
			FROM
				wcf".WCF_N."_option
			WHERE
					packageID = ?
				AND	optionName = ?";
		$stmt = \wcf\system\WCF::getDB()->prepareStatement($sql);
		$stmt->execute(array($packageID, 'signer_secret'));
		$this->optionID = $stmt->fetchColumn();
	}
	
	public function execute() {
		$sql = "UPDATE
				wcf".WCF_N."_option
			SET
				optionValue = ?
			WHERE
				optionID = ?";
		$stmt = \wcf\system\WCF::getDB()->prepareStatement($sql);
		$stmt->execute(array(\wcf\util\StringUtil::getRandomID(), $this->optionID));
		\wcf\data\option\OptionEditor::resetCache();
	}
}
$installation = new Installation($this->installation->getPackageID());
$installation->execute();
