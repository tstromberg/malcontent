
rule decryptor : medium {
  meta:
    description = "References 'dropper'"
    hash_2023_Downloads_016a = "016a1a4fe3e9d57ab0b2a11e37ad94cc922290d2499b8d96957c3ddbdc516d74"
    hash_2023_Downloads_016a = "016a1a4fe3e9d57ab0b2a11e37ad94cc922290d2499b8d96957c3ddbdc516d74"
    hash_2024_2024_Previewers = "20b986b24d86d9a06746bdb0c25e21a24cb477acb36e7427a8c465c08d51c1e4"
  strings:
    $ref = "dropper" fullword
    $ref2 = "Dropper" fullword
  condition:
    any of them
}
