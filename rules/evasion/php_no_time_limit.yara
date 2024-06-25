
rule php_no_time_limit : medium {
  meta:
    description = "disables execution time limit"
    hash_2024_2024_Inull_Studio_godzilla_xor_base64 = "699c7bbf08d2ee86594242f487860221def3f898d893071426eb05bec430968e"
    hash_2024_2024_sagsooz = "9f1821dbc40edebf4291abb64abc349c3fdf75eece9820c67ea00adf1a25aed4"
    hash_2023_0xShell_0xShellori = "506e12e4ce1359ffab46038c4bf83d3ab443b7c5db0d5c8f3ad05340cb09c38e"
  strings:
    $ref = "set_time_limit(0)"
  condition:
    $ref
}
