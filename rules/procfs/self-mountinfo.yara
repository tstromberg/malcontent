
rule proc_self_mountinfo : medium {
  meta:
    description = "gets mount info associated to this process"
    pledge = "stdio"
    hash_2023_Downloads_45b8 = "45b8678f74d29c87e2d06410245ab6c2762b76190594cafc9543fb9db90f3d4f"
    hash_2024_Downloads_4ba700b0e86da21d3dcd6b450893901c252bf817bd8792548fc8f389ee5aec78 = "fd3e21b8e2d8acf196cb63a23fc336d7078e72c2c3e168ee7851ea2bef713588"
    hash_2023_BlackCat_45b8 = "45b8678f74d29c87e2d06410245ab6c2762b76190594cafc9543fb9db90f3d4f"
  strings:
    $ref = "/proc/self/mountinfo"
  condition:
    $ref
}
