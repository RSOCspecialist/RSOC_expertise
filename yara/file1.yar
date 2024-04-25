import "hash"
import "pe"

rule file1{

meta:
	author = "ib_professional"
	description = "trojan malware file1"
condition:
	pe.imphash() == "c7269d59926fa4252270f407e4dab043" or hash.sha256(0, filesize) == "0992aa7f311e51cf84ac3ed7303b82664d7f2576598bf852dbf55d62cb101601"
}


