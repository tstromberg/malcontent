rule proc_mount_killer : high {
	meta:
		description = "kills processes with /proc/pid mounts"
	strings:
		$ref = /\/proc\/mounts.{0,32}\/proc\/\\d{0,32} xargs {0,6}kill -9/
	condition:
		$ref
}
