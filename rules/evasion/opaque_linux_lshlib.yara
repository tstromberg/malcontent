
rule opaque_linux_shlib : medium {
  meta:
	description = "ELF shared library without human readable content"
  strings:
    $word_with_spaces = /[a-z]{2,} [a-z]{2,}/
	$not_ld = "ld-linux"

	$has_malloc = "malloc" fullword
	$has_bss = "__bss_start" fullword
  condition:
    filesize < 1MB and uint32(0) == 1179403647 and #word_with_spaces == 0 and all of ($has*) and none of ($not*)
}

rule opaque_linux_shlib_io : high {
  meta:
	description = "ELF shared library that performs file operations without human readable content"
  strings:
	$has_write = "write" fullword
	$has_read = "read" fullword
	$has_fseek = "fseek" fullword
	$has_fprintf = "fprintf" fullword
	$has_fflush = "fflush" fullword
  condition:
	opaque_linux_shlib and all of ($has*)
}
