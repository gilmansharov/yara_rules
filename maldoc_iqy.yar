rule iqy_potential_malware_1
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

rule iqy_potential_malware_2
{
	meta:
		author = "Gil Mansharov"
		description = "Hunting potential iqy malware files - lots of potential FP (still can be bypassed)"
		reference = "https://blog.barkly.com/iqy-file-attack-malware-flawedammyy"
	strings:
		$1 = "WEB" nocase
		$2 = /\n1\s?\nhttps?:\/\/([\w\.-]+)([\/\w \.-]*)/ nocase
	condition:
		all of them and not uint16(0) == 0x5a4d
}
