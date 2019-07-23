package(default_visibility=["//visibility:public"])

cc_library(
    name = "subprocess",
    hdrs = ["subprocess.h"],
    copts = ["-fexceptions"],
    features = ["-use_header_modules"],
)

cc_library(
    name = "logging",
    srcs = ["logging.cc"],
    hdrs = ["logging.h"],
)

cc_library(
    name = "process-tools",
    srcs = ["process-tools.cc"],
    hdrs = ["process-tools.h"],
    deps = [
        ":logging",
        ":execution_statistics_cc_proto",
  ],
)

cc_binary(
    name = "linux-sandbox",
    srcs = [
            "linux-sandbox.cc",
            "linux-sandbox-options.cc",
            "linux-sandbox-options.h",
            "linux-sandbox-pid1.cc",
            "linux-sandbox-pid1.h",
    ],
    linkopts = ["-lm"],
    deps = [
            ":logging",
            ":process-tools",
    ],
    linkstatic = 1,
)

cc_library(
    name = "picosha2",
    hdrs = ["picosha2.h"],
    copts = ["-ftemplate-depth=1000000"],
)

cc_proto_library(
    name = "execution_statistics_cc_proto",
    deps = [":execution_statistics_proto"],
)

proto_library(
    name = "execution_statistics_proto",
    srcs = ["execution_statistics.proto"],
)

