rule cp_usr_lib_path : high {
	meta:
		description = "uses cp to install file to /usr/lib"
	strings:
		$ref = /cp -[\w \-\%]{3,16} \/usr\/lib\/[\w\.\-\/]{0,64}/ fullword
	condition:
		$ref
}
