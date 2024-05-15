
rule opaque_linux_shlib : medium {
  meta:
    description = "ELF shared library without human readable content"
    hash_2024_2023_ebury_8acf386 = "8acf386f61a34527ab7dde80ca9abbdc9c14d72537a7364484a4b32030ba93cd"
    hash_2024_2023_ebury_librwctl = "743d735be53444970d55efe67db57f9d6ff0b1ebfe170cd2847d5c9cdcc34d75"
  strings:
    $word_with_spaces = /[a-z]{2,} [a-z]{2,}/
    $not_ld = "ld-linux"
    $has_malloc = "malloc" fullword
    $has_static_vars = "__bss_start" fullword
  condition:
    filesize < 1048576 and uint32(0) == 1179403647 and #word_with_spaces == 0 and all of ($has*) and none of ($not*)
}

rule opaque_linux_shlib_io : high {
  meta:
    description = "ELF shared library that performs file operations without human readable content"
    hash_2024_2023_ebury_8acf386 = "8acf386f61a34527ab7dde80ca9abbdc9c14d72537a7364484a4b32030ba93cd"
    hash_2024_2023_ebury_librwctl = "743d735be53444970d55efe67db57f9d6ff0b1ebfe170cd2847d5c9cdcc34d75"
  strings:
    $has_write = "write" fullword
    $has_read = "read" fullword
    $has_fseek = "fseek" fullword
    $has_fprintf = "fprintf" fullword
    $has_fflush = "fflush" fullword
  condition:
    opaque_linux_shlib and all of ($has*)
}
