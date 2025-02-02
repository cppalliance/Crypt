# Copyright 2022, 2023 Peter Dimov
# Copyright 2024 Matt Borland
# Distributed under the Boost Software License, Version 1.0.
# https://www.boost.org/LICENSE_1_0.txt

local library = "crypt";

local triggers =
{
    branch: [ "master", "develop", "feature/*" ]
};

local ubsan = { UBSAN: '1', UBSAN_OPTIONS: 'print_stacktrace=1' };
local asan = { ASAN: '1' };

local linux_pipeline(name, image, environment, packages = "", sources = [], arch = "amd64") =
{
    name: name,
    kind: "pipeline",
    type: "docker",
    trigger: triggers,
    platform:
    {
        os: "linux",
        arch: arch
    },
    clone:
    {
        retries: 5,
    },
    steps:
    [
        {
            name: "everything",
            image: image,
            privileged: true,
            environment: environment,
            commands:
            [
                'set -e',
                'wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -',
            ] +
            (if sources != [] then [ ('apt-add-repository "' + source + '"') for source in sources ] else []) +
            (if packages != "" then [ 'apt-get update', 'apt-get -y install ' + packages ] else []) +
            [
                'export LIBRARY=' + library,
                './.drone/drone.sh',
            ]
        }
    ]
};

local macos_pipeline(name, environment, xcode_version = "12.2", osx_version = "catalina", arch = "amd64") =
{
    name: name,
    kind: "pipeline",
    type: "exec",
    trigger: triggers,
    platform: {
        "os": "darwin",
        "arch": arch
    },
    node: {
        "os": osx_version
    },
    steps: [
        {
            name: "everything",
            environment: environment + { "DEVELOPER_DIR": "/Applications/Xcode-" + xcode_version + ".app/Contents/Developer" },
            commands:
            [
                'export LIBRARY=' + library,
                './.drone/drone.sh',
            ]
        }
    ]
};

local windows_pipeline(name, image, environment, arch = "amd64") =
{
    name: name,
    kind: "pipeline",
    type: "docker",
    trigger: triggers,
    platform:
    {
        os: "windows",
        arch: arch
    },
    "steps":
    [
        {
            name: "everything",
            image: image,
            environment: environment,
            commands:
            [
                'cmd /C .drone\\\\drone.bat ' + library,
            ]
        }
    ]
};

[

    linux_pipeline(
        "Linux 22.04 GCC 11 ARM64",
        "cppalliance/droneubuntu2204:multiarch",
        { TOOLSET: 'gcc', COMPILER: 'g++', CXXSTD: '03,11,14,17,2a' },
        arch="arm64",
    ),

    linux_pipeline(
        "Linux 22.04 GCC 11 ARM64 - ASAN",
        "cppalliance/droneubuntu2204:multiarch",
        { TOOLSET: 'gcc', COMPILER: 'g++', CXXSTD: '03,11,14,17,2a' } + asan,
        arch="arm64",
    ),

    linux_pipeline(
        "Linux 22.04 GCC 11 S390x",
        "cppalliance/droneubuntu2204:multiarch",
        { TOOLSET: 'gcc', COMPILER: 'g++', CXXSTD: '03,11,14,17,2a' },
        arch="s390x",
    ),

    linux_pipeline(
        "Linux 22.04 GCC 11 32/64",
        "cppalliance/droneubuntu2204:1",
        { TOOLSET: 'gcc', COMPILER: 'g++', CXXSTD: '03,11,14,17,2a', ADDRMD: '32,64' },
    ),

    linux_pipeline(
        "Linux 22.04 GCC 12 32 ASAN",
        "cppalliance/droneubuntu2204:1",
        { TOOLSET: 'gcc', COMPILER: 'g++-12', CXXSTD: '20,2b', ADDRMD: '32' } + asan,
        "g++-12-multilib",
    ),

    linux_pipeline(
        "Linux 22.04 GCC 12 64 ASAN",
        "cppalliance/droneubuntu2204:1",
        { TOOLSET: 'gcc', COMPILER: 'g++-12', CXXSTD: '03,11,14,17,20,2b', ADDRMD: '64' } + asan,
        "g++-12-multilib",
    ),
    
    linux_pipeline(
        "Linux 24.04 GCC 13 32/64",
        "cppalliance/droneubuntu2404:1",
        { TOOLSET: 'gcc', COMPILER: 'g++-13', CXXSTD: '03,11,14,17,20,23', ADDRMD: '32,64', CXXFLAGS: "-fexcess-precision=fast" },
        "g++-13-multilib",
    ),

    linux_pipeline(
        "Linux 24.04 GCC 13 GNU 32/64",
        "cppalliance/droneubuntu2404:1",
        { TOOLSET: 'gcc', COMPILER: 'g++-13', CXXSTD: '03,11,14,17,20,23', ADDRMD: '32,64', CXXFLAGS: "-fexcess-precision=fast", CXXSTDDIALECT: "gnu" },
        "g++-13-multilib",
    ),

    linux_pipeline(
        "Linux 24.04 GCC 14 32",
        "cppalliance/droneubuntu2404:1",
        { TOOLSET: 'gcc', COMPILER: 'g++-14', CXXSTD: '03,11,14,17,20,23', ADDRMD: '32', CXXFLAGS: "-fexcess-precision=fast" },
        "g++-14-multilib",
    ),

    linux_pipeline(
        "Linux 24.04 GCC 14 64",
        "cppalliance/droneubuntu2404:1",
        { TOOLSET: 'gcc', COMPILER: 'g++-14', CXXSTD: '03,11,14,17,20,23', ADDRMD: '64', CXXFLAGS: "-fexcess-precision=fast" },
        "g++-14-multilib",
    ),

    linux_pipeline(
        "Linux 24.04 GCC 14 GNU 32",
        "cppalliance/droneubuntu2404:1",
        { TOOLSET: 'gcc', COMPILER: 'g++-14', CXXSTD: '03,11,14,17,20,23', ADDRMD: '32', CXXFLAGS: "-fexcess-precision=fast", CXXSTDDIALECT: "gnu" },
        "g++-14-multilib",
    ),

    linux_pipeline(
        "Linux 24.04 GCC 14 GNU 64",
        "cppalliance/droneubuntu2404:1",
        { TOOLSET: 'gcc', COMPILER: 'g++-14', CXXSTD: '03,11,14,17,20,23', ADDRMD: '64', CXXFLAGS: "-fexcess-precision=fast", CXXSTDDIALECT: "gnu" },
        "g++-14-multilib",
    ),

    linux_pipeline(
        "Linux 22.04 Clang 16",
        "cppalliance/droneubuntu2204:1",
        { TOOLSET: 'clang', COMPILER: 'clang++-16', CXXSTD: '03,11,14,17,20,2b' },
        "clang-16",
        ["deb http://apt.llvm.org/jammy/ llvm-toolchain-jammy-16 main"],
    ),

    linux_pipeline(
        "Linux 24.04 Clang 17",
        "cppalliance/droneubuntu2404:1",
        { TOOLSET: 'clang', COMPILER: 'clang++-17', CXXSTD: '03,11,14,17,20,2b' },
        "clang-17",
        ["deb http://apt.llvm.org/jammy/ llvm-toolchain-jammy-17 main"],
    ),

    linux_pipeline(
        "Linux 24.04 Clang 18",
        "cppalliance/droneubuntu2404:1",
        { TOOLSET: 'clang', COMPILER: 'clang++-18', CXXSTD: '03,11,14,17,20,2b' },
        "clang-18",
        ["deb http://apt.llvm.org/noble/ llvm-toolchain-noble-18 main"],
    ),

    linux_pipeline(
        "Linux 24.04 Clang 19",
        "cppalliance/droneubuntu2404:1",
        { TOOLSET: 'clang', COMPILER: 'clang++-19', CXXSTD: '03,11,14,17,20,2b' },
        "clang-19",
        ["deb http://apt.llvm.org/noble/ llvm-toolchain-noble-19 main"],
    ),

    linux_pipeline(
        "Linux 24.04 Clang 19 UBSAN",
        "cppalliance/droneubuntu2404:1",
        { TOOLSET: 'clang', COMPILER: 'clang++-19', CXXSTD: '03,11,14,17,20,2b' } + ubsan,
        "clang-19",
        ["deb http://apt.llvm.org/noble/ llvm-toolchain-noble-19 main"],
    ),

    linux_pipeline(
        "Linux 24.04 Clang 19 ASAN",
        "cppalliance/droneubuntu2404:1",
        { TOOLSET: 'clang', COMPILER: 'clang++-19', CXXSTD: '03,11,14,17,20,2b' } + asan,
        "clang-19",
        ["deb http://apt.llvm.org/noble/ llvm-toolchain-noble-19 main"],
    ),

    windows_pipeline(
        "Windows VS2019 msvc-14.2",
        "cppalliance/dronevs2019",
        { TOOLSET: 'msvc-14.2', CXXSTD: '14,17,20,latest' },
    ),

    windows_pipeline(
        "Windows VS2022 msvc-14.3",
        "cppalliance/dronevs2022:1",
        { TOOLSET: 'msvc-14.3', CXXSTD: '14,17,20,latest' },
    ),
]
