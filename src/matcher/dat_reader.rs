//! V2Ray .dat 文件（GeoSite 和 GeoIP 的）的 protobuf 分帧：字段头和长度都是变长整数，按线上类型跳过不要的字段，
//! 越出所在消息的字段就是坏文件
//! The protobuf framing of V2Ray .dat files (GeoSite's and GeoIP's): keys and lengths are
//! varints, unwanted fields are skipped by wire type, and a field running past its message
//! means a broken file

use std::fs;
use std::io::Read;
use std::path::Path;

use anyhow::Context;

/// .dat 文件的顺序读取：按需读出字段、跳过不要的部分，不把整个文件读进内存。GeoSite 和 GeoIP 的 .dat 都这样读，
/// 读到的消息再交给 prost 解
/// Sequential reading of a .dat file: fields are read as needed and the rest skipped, without
/// reading the whole file into memory. GeoSite and GeoIP .dat files are both read so, the
/// messages read handed to prost to decode
pub(super) struct DatReader {
    file: std::io::BufReader<fs::File>,
    /// 当前在文件里的位置 / The current position in the file
    pos: usize,
    /// 打开时的文件长度 / The file's length when opened
    len: usize,
}

impl DatReader {
    pub(super) fn open(path: &Path) -> anyhow::Result<Self> {
        let file = fs::File::open(path)?;
        let len = usize::try_from(file.metadata()?.len())?;
        Ok(Self {
            file: std::io::BufReader::with_capacity(64 * 1024, file),
            pos: 0,
            len,
        })
    }

    /// 当前在文件里的位置 / The current position in the file
    pub(super) fn pos(&self) -> usize {
        self.pos
    }

    /// 文件的结尾（打开时的长度）/ The end of the file (its length when opened)
    pub(super) fn end(&self) -> usize {
        self.len
    }

    /// 下一个字节，必须有 / The next byte, which must be there
    fn next_byte(&mut self) -> anyhow::Result<u8> {
        anyhow::ensure!(self.pos < self.len, "unexpected end of file");
        let mut byte = [0u8];
        self.file.read_exact(&mut byte)?;
        self.pos += 1;
        Ok(byte[0])
    }

    /// 读一个变长整数：最多 10 个字节，多了就是坏文件 / Reads a varint: 10 bytes at most,
    /// more means a broken file
    fn varint(&mut self) -> anyhow::Result<usize> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let byte = self.next_byte()?;
            value |= u64::from(byte & 0x7F) << shift;
            if byte & 0x80 == 0 {
                return varint_len(value);
            }
        }
        anyhow::bail!("invalid varint in .dat file")
    }

    /// 从当前位置往后读到 `end` 为止，找下一个字段号是 `number` 的字段，给出它的值有多长，读的位置停在值的开头；
    /// 别的字段按线上类型跳过。字段头和长度都是变长整数。找的字段不是带长度的、哪个字段越出 `end`、线上类型不认识，
    /// 都是坏文件，报错：调用方整份拒绝，不把读到的那部分当成完整的文件。读到 `end` 也没找到时是 None
    /// Reads on from the current position up to `end` for the next field numbered `number`,
    /// giving the length of its value with the position left where the value starts; other
    /// fields are skipped by wire type. Keys and lengths are varints. The field not being
    /// length-delimited, any field running past `end`, or a wire type not known means a
    /// broken file and an error: callers refuse the whole file rather than take the part read
    /// for all of it. None when `end` is reached without finding it
    pub(super) fn next_field(
        &mut self,
        number: usize,
        end: usize,
    ) -> anyhow::Result<Option<usize>> {
        while self.pos < end {
            let key = self.varint()?;
            let (field, wire_type) = (key >> 3, key & 0x07);
            let len = match wire_type {
                0 => {
                    self.varint()?;
                    0
                }
                1 => 8,
                2 => self.varint()?,
                5 => 4,
                other => anyhow::bail!("invalid wire type {other} in .dat file"),
            };
            if runs_past(self.pos, len, end) {
                anyhow::bail!(
                    "truncated .dat file: field {field} at offset {} needs {len} bytes, past the end of its message at {end}",
                    self.pos
                );
            }
            if field == number {
                anyhow::ensure!(
                    wire_type == 2,
                    "invalid wire type {wire_type} for field {number} in .dat file"
                );
                return Ok(Some(len));
            }
            self.seek_to(self.pos + len)?;
        }
        Ok(None)
    }

    /// 接下来的 `len` 个字节，读进 `buf` / The next `len` bytes, read into `buf`
    pub(super) fn read(&mut self, buf: &mut Vec<u8>, len: usize) -> anyhow::Result<()> {
        buf.clear();
        buf.resize(len, 0);
        self.file.read_exact(buf)?;
        self.pos += len;
        Ok(())
    }

    /// 移到文件里的 `pos` / Moves to `pos` in the file
    pub(super) fn seek_to(&mut self, pos: usize) -> anyhow::Result<()> {
        let offset = i64::try_from(pos)? - i64::try_from(self.pos)?;
        self.file.seek_relative(offset)?;
        self.pos = pos;
        Ok(())
    }
}

/// 变长整数当作长度或位置用 / A varint used as a length or position
fn varint_len(value: u64) -> anyhow::Result<usize> {
    usize::try_from(value).context("varint in .dat file too large")
}

/// 从 `pos` 起的 `len` 个字节是否越出 `end`。`len` 是文件里读出来的，可以接近 u64::MAX：
/// 加起来溢出也算越出，不能让回绕成的小数通过检查、把读的位置退回前面
/// Whether `len` bytes from `pos` run past `end`. `len` is read from the file and may come
/// close to u64::MAX: a sum that overflows runs past too, rather than wrapping to a small
/// number that passes the check and moves the reading position back
fn runs_past(pos: usize, len: usize, end: usize) -> bool {
    pos.checked_add(len).is_none_or(|stop| stop > end)
}
