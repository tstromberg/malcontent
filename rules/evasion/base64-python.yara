
rule base64_python_functions : critical {
  meta:
    description = "contains base64 Python code"
    hash_2024_2024_PAN_OS_Upstyle_update = "3de2a4392b8715bad070b2ae12243f166ead37830f7c6d24e778985927f9caac"
    hash_2024_2024_PAN_OS_Upstyle_update_base64_payload1 = "e96f6ca8ecc00fcfac88679e475022091ce47f75c54f47570d66a56d77cd5ea6"
    hash_2024_2024_Spinning_YARN_yarn_fragments = "723326f8551f2a92ccceeec93859f58df380a3212e7510bc64181f2a0743231c"
  strings:
    $exec = "exec(" base64
    $eval = "eval(" base64
    $import_os = "import os" base64
    $import = "__import__" base64
    $importlib = "importlib" base64
    $import_module = "import_module" base64
    $urllib = "urllib.request" base64
    $requests_get = "requests.get" base64
    $urlopen = "urlopen" base64
    $read = "read()" base64
    $decode = "decode()" base64
    $b64decode = "base64.b64decode" base64
    $exc = "except Exception as" base64
    $thread = "threading.Thread" base64
  condition:
    2 of them
}
