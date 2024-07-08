rule cp_run_rm : high {
	meta:
		description = "uses shell to copy, run, and remove"
	strings:
		$ref = /cp -[\w \-\%\&\.\/\>]{3,64} \&\& \.{0,1}\/[\/\w\.\- \>\& ]{1,48} \&\& rm \-\w{1,2} [\w \-\%\&\.\/\>]{1,32}/
	condition:
		$ref
}
