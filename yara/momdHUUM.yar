import "hash"
import "pe"

rule momdHUUM{

meta:
	author = "ib_professional"
	description = "trojan malware momdHUUM"
condition:
	pe.imphash() == "4749670ac3d28d6761142b0dcb4f5076" or hash.sha256(0, filesize) == "3c2fe308c0a563e06263bbacf793bbe9b2259d795fcc36b953793a7e499e7f71"
}


