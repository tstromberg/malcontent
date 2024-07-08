
rule dev_shm : medium {
  meta:
    description = "references /dev/shm and /proc/self/exe - possible UPX-based packer"
  strings:
    $ref = /\/dev\/shm[\%\w\-\/\.]{0,64}/
	$ref2 = "/proc/self/exe"
  condition:
    all of them
}