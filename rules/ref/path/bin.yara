rule bin_path : low {
	meta:
		description = "path reference within /bin"
	strings:
		$ref = /\/bin\/[\w\.\-\/]{0,64}/ fullword
	condition:
		$ref
}

