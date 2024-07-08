rule cp_bin_path : high {
	meta:
		description = "uses cp to install file to /bin"
	strings:
		$ref = /cp -[\w \-\%]{3,16} \/bin\/[\w\.\-\/]{0,64}/ fullword
	condition:
		$ref
}

rule cp_usr_bin_path : high {
	meta:
		description = "uses cp to install file to /usr/bin"
	strings:
		$ref = /cp -[\w \-\%]{3,16} \/usr\/bin\/[\w\.\-\/]{0,64}/ fullword
	condition:
		$ref
}
