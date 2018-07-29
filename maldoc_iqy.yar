rule iqy_potential_malware
{
	meta:
		author = "Gil Mansharov"
		description = "Hunting potential iqy malware files - easy to bypass"
		reference = "https://blog.barkly.com/iqy-file-attack-malware-flawedammyy"
	strings:
		$pattern = /WEB\s?\n1\s?\nhttps?:\/\/([\w\.-]+)([\/\w \.-]*)/ nocase
	condition:
		$pattern and not uint16(0) == 0x5a4d
}
