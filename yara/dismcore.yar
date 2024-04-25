import "hash"
import "pe"

rule dismcore{

meta:
	author = "ib_professional"
	description = "trojan malware dismcore"
condition:
	pe.imphash() == "9806a0b167048a1d9ebada277d5a611f" or hash.sha256(0, filesize) == "01fba22c3e6cf11805afe4ba2f7c303813c83486e07b2b418bf1b3fabfd2544e"
}


