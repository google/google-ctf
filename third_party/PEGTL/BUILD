cc_library(
    name = "pegtl",
    copts = [
        "-fexceptions",
        "-Wno-google3-inline-namespace",
    ],
    features = ["-use_header_modules"],
    includes = [
        ".",
        "include",
        "include/tao",
        "include/tao/pegtl",
    ],
    textual_hdrs = glob(["include/**/*"]),
)
