import "hash"
import "pe"

rule NetSess{

meta:
	author = "ib_professional"
	description = "trojan malware NetSess"
condition:
	pe.imphash() == "eb58ec33006402a91db972c2fceb92ab" or hash.sha256(0, filesize) == "ddeeedc8ab9ab3b90c2e36340d4674fda3b458c0afd7514735b2857f26b14c6d"
}


