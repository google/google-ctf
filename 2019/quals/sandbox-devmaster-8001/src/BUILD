package(default_visibility=["//visibility:public"])

cc_binary(
    name = "server",
    srcs = ["server.cc"],
    copts = ["-fexceptions"],
    features = ["-use_header_modules"],
    deps = ["//third_party:subprocess"],
    linkopts = ["-pthread"],
    linkstatic = 1,
)

cc_binary(
    name = "client",
    srcs = ["client.cc"],
    copts = ["-fexceptions"],
    features = ["-use_header_modules"],
    deps = [":client_lib"],
    linkopts = ["-pthread"],
    linkstatic = 1,
)

cc_library(
    name = "client_lib",
    hdrs = ["client_lib.h"],
    copts = ["-fexceptions"],
    deps = ["//third_party:subprocess"],
    features = ["-use_header_modules"],
)

cc_binary(
    name = "executor",
    srcs = ["executor.cc"],
    linkstatic = 1,
)

cc_binary(
    name = "drop_privs",
    srcs = ["drop_privs.cc"],
    linkstatic = 1,
)

cc_binary(
    name = "admin",
    srcs = ["admin.cc"],
    deps = ["//third_party:picosha2"],
    copts = ["-ftemplate-depth=1000000"],
    linkstatic = 1,
)

cc_binary(
    name = "admin_builder_client",
    srcs = ["admin_builder_client.cc"],
    copts = ["-fexceptions"],
    features = ["-use_header_modules"],
    deps = [":client_lib"],
    linkopts = ["-pthread"],
    linkstatic = 1,
)


cc_binary(
    name = "multiplexer",
    srcs = ["multiplexer.cc"],
    linkopts = ["-pthread"],
    copts = ["--std=c++17"],
    deps = ["//third_party:subprocess"],
)
