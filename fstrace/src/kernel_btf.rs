//! Read member offsets from the running kernel, never from build-host layouts.

use anyhow::{Context, Result, bail, ensure};

pub fn member_offset(bytes: &[u8], structure: &str, member: &str) -> Result<u32> {
    fn word(bytes: &[u8], offset: usize) -> Result<u32> {
        Ok(u32::from_le_bytes(
            bytes
                .get(offset..offset + 4)
                .context("truncated kernel BTF")?
                .try_into()?,
        ))
    }
    ensure!(
        bytes.get(..2) == Some(&[0x9f, 0xeb]),
        "unsupported kernel BTF byte order"
    );
    let header = word(bytes, 4)? as usize;
    let type_start = header
        .checked_add(word(bytes, 8)? as usize)
        .context("BTF type offset overflow")?;
    let type_end = type_start
        .checked_add(word(bytes, 12)? as usize)
        .context("BTF type length overflow")?;
    let strings_start = header
        .checked_add(word(bytes, 16)? as usize)
        .context("BTF string offset overflow")?;
    let strings_end = strings_start
        .checked_add(word(bytes, 20)? as usize)
        .context("BTF string length overflow")?;
    let types = bytes
        .get(type_start..type_end)
        .context("invalid BTF type section")?;
    let strings = bytes
        .get(strings_start..strings_end)
        .context("invalid BTF string section")?;
    let name = |offset: u32| -> Result<&str> {
        let tail = strings.get(offset as usize..).context("invalid BTF name")?;
        let length = tail
            .iter()
            .position(|byte| *byte == 0)
            .context("unterminated BTF name")?;
        Ok(std::str::from_utf8(&tail[..length])?)
    };
    let mut at = 0;
    while at < types.len() {
        let info = word(types, at + 4)?;
        let kind = (info >> 24) & 31;
        let count = (info & 0xffff) as usize;
        if kind == 4 && name(word(types, at)?)? == structure {
            for index in 0..count {
                let entry = at + 12 + index * 12;
                if name(word(types, entry)?)? == member {
                    let mut bits = word(types, entry + 8)?;
                    if info >> 31 != 0 {
                        ensure!(bits >> 24 == 0, "BTF member is a bitfield");
                        bits &= 0x00ff_ffff;
                    }
                    ensure!(bits % 8 == 0, "unaligned BTF member");
                    return Ok(bits / 8);
                }
            }
            bail!("kernel BTF lacks {structure}.{member}");
        }
        let extra = match kind {
            1 | 14 | 17 => 4,
            3 => 12,
            4 | 5 | 15 | 19 => count * 12,
            6 | 13 => count * 8,
            2 | 7..=12 | 16 | 18 => 0,
            _ => bail!("unsupported kernel BTF kind {kind}"),
        };
        at += 12 + extra;
        ensure!(at <= types.len(), "truncated BTF type record");
    }
    bail!("kernel BTF lacks structure {structure}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vec<u8> {
        let words = [
            0x0001_eb9f,
            24,
            0,
            24,
            24,
            18,
            1,
            (4 << 24) | 1,
            8,
            13,
            0,
            32,
        ];
        let mut bytes: Vec<_> = words.into_iter().flat_map(u32::to_le_bytes).collect();
        bytes.extend_from_slice(b"\0task_struct\0pid\0\0");
        bytes
    }

    #[test]
    fn reads_named_field_and_rejects_missing_or_truncated_data() {
        let bytes = fixture();
        assert_eq!(member_offset(&bytes, "task_struct", "pid").unwrap(), 4);
        assert!(member_offset(&bytes, "task_struct", "cred").is_err());
        assert!(member_offset(&bytes, "missing", "pid").is_err());
        for end in 0..bytes.len() {
            assert!(member_offset(&bytes[..end], "task_struct", "pid").is_err());
        }
    }
}
