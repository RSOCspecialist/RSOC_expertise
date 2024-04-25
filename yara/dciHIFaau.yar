import "hash"
import "pe"

rule dciHIFaau{

meta:
	author = "ib_professional"
	description = "trojan malware dciHIFaau"
condition:
	hash.sha256(0, filesize) == "0e545a54f3cfef84bb59be1a95453ae4b34b5464b0f5ca618a0da2e4c97c7526" or re.imphash() == "74080ab285ec9a90f6a961545702c313"
}


