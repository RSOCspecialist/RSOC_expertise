import "hash"
import "pe"

rule sshins{

meta:
	author = "ib_professional"
	description = "trojan malware sshins"
condition:
	hash.sha256(0, filesize) == "ab9cc4ee82aa6f57ba2a113aab905c33e278c969399db4188d0ea5942ad3bb7d"
}


