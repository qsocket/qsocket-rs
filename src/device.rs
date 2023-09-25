
#[repr(u8)]
#[derive(Copy, Clone)]
pub enum DeviceArch {
    Unknown = 0,
    I686,
    X86_64,
    Aarch64,
    Arm,
    ArmV7,
    Mips,
    Mips64,
    Mips64el,
    Mipsel,
    PowerPC,
    PowerPC64,
    PowerPC64le,
    S390X,
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
    Solaris,
    Illumos,
    Wasm,
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
        "wasm" => DeviceOS::Wasm,
        _ => DeviceOS::Unknown,
    }
}

pub fn get_device_arch() -> DeviceArch {
    // Determine architecture...
    match std::env::consts::ARCH {
        "x86_64" => DeviceArch::X86_64,
        "i686" => DeviceArch::I686,
        "aarch64" => DeviceArch::Aarch64,
        "arm" => DeviceArch::Arm,
        "armv7" => DeviceArch::ArmV7,
        "mips" => DeviceArch::Mips,
        "mips64" => DeviceArch::Mips64,
        "mips64le" => DeviceArch::Mips64el,
        "mipsel" => DeviceArch::Mipsel,
        "powerpc" => DeviceArch::PowerPC,
        "powerpc64" => DeviceArch::PowerPC64,
        "powerpc64le" => DeviceArch::PowerPC64le,
        "s390x" => DeviceArch::S390X,
        "wasm32" => DeviceArch::Wasm,
        "wasm64" => DeviceArch::Wasm,
        _ => DeviceArch::Unknown,
    }
}

