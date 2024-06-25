import "math"

private rule pySetup {
  strings:
    $i_distutils = "from distutils.core import setup"
    $i_setuptools = "setuptools"
    $setup = "setup("
  condition:
    filesize < 2097152 and $setup and any of ($i*)
}

rule py_marshal : notable {
  meta:
    description = "reads python values from binary content"
    hash_2024_2021_DiscordSafety_setup = "7dfa21dda6b275952ee8410a19b0f38e1071588be5894cf052329ca106eae6e1"
  strings:
    $ref = "import marshal"
  condition:
    any of them
}

rule setuptools_py_marshal : suspicious {
  meta:
    description = "Python library installer that reads values from binary content"
  condition:
    pySetup and py_marshal
}
