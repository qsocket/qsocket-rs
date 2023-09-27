#[repr(u8)]
#[derive(Copy, Clone)]
pub enum DeviceArch {
    Unknown = 0,
    I686,
    AMD64,
    AMD64P32,
    Arm,
    Arm64,
    Arm64be,
    Armbe,
    Loong64,
    Mips,
    Mips64,
    Mips64le,
    Mips64p32,
    Mips64p32le,
    Mipsle,
    PowerPC,
    PowerPC64,
    PowerPC64le,
    Riscv,
    Riscv64,
    S390,
    S390X,
    Sparc,
    Sparc64,
    Wasm,
}

#[repr(u8)]
#[derive(Copy, Clone)]
pub enum DeviceOS {
    Unknown = 0,
    Linux,
    Darwin,
    Windows,
    Android,
    Ios,
    FreeBSD,
    OpenBSD,
    NetBSD,
    Wasm,
    Solaris,
    Dragonfly,
    Illumos,
    Aix,
    Zos,
    Nacl,
    Plan9,
    Hurd,
}

pub fn get_device_os() -> DeviceOS {
    // Determine OS...
    match std::env::consts::OS {
        "linux" => DeviceOS::Linux,
        "windows" => DeviceOS::Windows,
        "macos" => DeviceOS::Darwin,
        "android" => DeviceOS::Android,
        "ios" => DeviceOS::Ios,
        "freebsd" => DeviceOS::FreeBSD,
        "openbsd" => DeviceOS::OpenBSD,
        "netbsd" => DeviceOS::NetBSD,
        "solaris" => DeviceOS::Solaris,
        "illumos" => DeviceOS::Illumos,
        "dragonfly" => DeviceOS::Dragonfly,
        "aix" => DeviceOS::Aix,
        "wasm" => DeviceOS::Wasm,
        "hurd" => DeviceOS::Hurd,
        _ => DeviceOS::Unknown,
    }
}

pub fn get_device_arch() -> DeviceArch {
    // Determine architecture...
    match std::env::consts::ARCH {
        "x86_64" => DeviceArch::AMD64,
        "i686" => DeviceArch::I686,
        "aarch64" => DeviceArch::Arm64,
        "aarch64_be" => DeviceArch::Arm64be,
        "arm" => DeviceArch::Arm,
        "armv7" => DeviceArch::Arm,
        "mips" => DeviceArch::Mips,
        "mips64" => DeviceArch::Mips64,
        "mips64el" => DeviceArch::Mips64le,
        "mipsel" => DeviceArch::Mipsle,
        "powerpc" => DeviceArch::PowerPC,
        "powerpc64" => DeviceArch::PowerPC64,
        "powerpc64le" => DeviceArch::PowerPC64le,
        "sparc" => DeviceArch::Sparc,
        "sparc64" => DeviceArch::Sparc64,
        "riscv64" => DeviceArch::Riscv64,
        "riscv32gc" => DeviceArch::Riscv,
        "loongarch64" => DeviceArch::Loong64,
        "s390x" => DeviceArch::S390X,
        "wasm32" => DeviceArch::Wasm,
        "wasm64" => DeviceArch::Wasm,
        _ => DeviceArch::Unknown,
    }
}
