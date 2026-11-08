use anyhow::{Result, bail};
use clap::ValueEnum;

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Architecture {
    X86_64,
    Aarch64,
}

impl Architecture {
    pub fn native() -> Result<Self> {
        match std::env::consts::ARCH {
            "x86_64" => Ok(Self::X86_64),
            "aarch64" => Ok(Self::Aarch64),
            arch => bail!("unsupported host architecture {arch:?}; select --arch explicitly"),
        }
    }

    pub fn musl_target(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64-unknown-linux-musl",
            Self::Aarch64 => "aarch64-unknown-linux-musl",
        }
    }

    pub fn debian(self) -> &'static str {
        match self {
            Self::X86_64 => "amd64",
            Self::Aarch64 => "arm64",
        }
    }

    pub fn platform(self) -> &'static str {
        match self {
            Self::X86_64 => "linux/amd64",
            Self::Aarch64 => "linux/arm64",
        }
    }

    pub fn qemu(self) -> &'static str {
        match self {
            Self::X86_64 => "qemu-system-x86_64",
            Self::Aarch64 => "qemu-system-aarch64",
        }
    }

    pub fn console(self) -> &'static str {
        match self {
            Self::X86_64 => "console=ttyS0 panic=-1 loglevel=4",
            Self::Aarch64 => "console=ttyAMA0 panic=-1 loglevel=4",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn architecture_settings_stay_consistent() {
        for (arch, target, debian, platform, qemu, console) in [
            (
                Architecture::X86_64,
                "x86_64-unknown-linux-musl",
                "amd64",
                "linux/amd64",
                "qemu-system-x86_64",
                "console=ttyS0 panic=-1 loglevel=4",
            ),
            (
                Architecture::Aarch64,
                "aarch64-unknown-linux-musl",
                "arm64",
                "linux/arm64",
                "qemu-system-aarch64",
                "console=ttyAMA0 panic=-1 loglevel=4",
            ),
        ] {
            assert_eq!(arch.musl_target(), target);
            assert_eq!(arch.debian(), debian);
            assert_eq!(arch.platform(), platform);
            assert_eq!(arch.qemu(), qemu);
            assert_eq!(arch.console(), console);
        }
    }
}
