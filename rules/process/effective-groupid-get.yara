
rule getegid : harmless {
  meta:
    syscall = "getegid"
    description = "returns the effective group id of the current process"
  strings:
    $getuid = "getegid" fullword
    $Getuid = "Getegid" fullword
  condition:
    any of them
}

rule php_getmygid : medium {
  meta:
    syscall = "getegid"
    description = "returns the effective group id of the current process"
    hash_2024_2024_sagsooz = "9f1821dbc40edebf4291abb64abc349c3fdf75eece9820c67ea00adf1a25aed4"
    hash_2023_0xShell_0xShellori = "506e12e4ce1359ffab46038c4bf83d3ab443b7c5db0d5c8f3ad05340cb09c38e"
    hash_2023_0xShell_root = "3baa3bfaa6ed78e853828f147c3747d818590faee5eecef67748209dd3d92afb"
  strings:
    $getmygid = "getmygid"
  condition:
    any of them
}
