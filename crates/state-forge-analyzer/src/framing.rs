/// Порядок байтов для целочисленных заголовков длины
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Endianness {
    BigEndian,
    LittleEndian,
}

/// Трейт для выделения логических кадров из накопительного TCP байт-потока
pub trait FrameDelineator {
    /// Извлекает все готовые фреймы из буфера, удаляя прочитанные байты из начала `buffer`
    fn extract_frames(&mut self, buffer: &mut Vec<u8>) -> Vec<Vec<u8>>;
}

/// Демаркатор фреймов на основе префикса длины (например, 2 байта или 4 байта длины)
#[derive(Debug, Clone)]
pub struct LengthPrefixedDelineator {
    pub header_bytes: usize,
    pub endianness: Endianness,
    pub length_includes_header: bool,
    pub max_frame_len: usize,
}

impl LengthPrefixedDelineator {
    pub fn new(header_bytes: usize, endianness: Endianness) -> Self {
        Self {
            header_bytes,
            endianness,
            length_includes_header: false,
            max_frame_len: 16 * 1024 * 1024,
        }
    }

    pub fn with_includes_header(mut self, includes: bool) -> Self {
        self.length_includes_header = includes;
        self
    }

    pub fn with_max_len(mut self, max_len: usize) -> Self {
        self.max_frame_len = max_len;
        self
    }

    fn parse_length(&self, header: &[u8]) -> Option<usize> {
        let len = match self.header_bytes {
            1 => header[0] as usize,
            2 => {
                let bytes: [u8; 2] = header[..2].try_into().ok()?;
                match self.endianness {
                    Endianness::BigEndian => u16::from_be_bytes(bytes) as usize,
                    Endianness::LittleEndian => u16::from_le_bytes(bytes) as usize,
                }
            }
            4 => {
                let bytes: [u8; 4] = header[..4].try_into().ok()?;
                match self.endianness {
                    Endianness::BigEndian => u32::from_be_bytes(bytes) as usize,
                    Endianness::LittleEndian => u32::from_le_bytes(bytes) as usize,
                }
            }
            8 => {
                let bytes: [u8; 8] = header[..8].try_into().ok()?;
                match self.endianness {
                    Endianness::BigEndian => u64::from_be_bytes(bytes) as usize,
                    Endianness::LittleEndian => u64::from_le_bytes(bytes) as usize,
                }
            }
            _ => return None,
        };
        Some(len)
    }
}

impl FrameDelineator for LengthPrefixedDelineator {
    fn extract_frames(&mut self, buffer: &mut Vec<u8>) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();

        while buffer.len() >= self.header_bytes {
            let body_len = match self.parse_length(&buffer[..self.header_bytes]) {
                Some(len) => len,
                None => break,
            };

            let total_frame_len = if self.length_includes_header {
                if body_len < self.header_bytes {
                    // Ошибочная длина меньше самого заголовка
                    break;
                }
                body_len
            } else {
                self.header_bytes + body_len
            };

            if total_frame_len > self.max_frame_len {
                // Превышение лимита длины фрейма
                break;
            }

            if buffer.len() < total_frame_len {
                // Кадр еще не поступил целиком
                break;
            }

            // Извлекаем кадр целиком
            let frame = buffer.drain(..total_frame_len).collect();
            frames.push(frame);
        }

        frames
    }
}

/// Демаркатор фреймов по разделителю (например, "\r\n\r\n" для HTTP или "\n" для текстовых строк)
#[derive(Debug, Clone)]
pub struct DelimiterDelineator {
    pub delimiter: Vec<u8>,
    pub keep_delimiter: bool,
}

impl DelimiterDelineator {
    pub fn new(delimiter: &[u8]) -> Self {
        Self {
            delimiter: delimiter.to_vec(),
            keep_delimiter: true,
        }
    }

    pub fn with_keep_delimiter(mut self, keep: bool) -> Self {
        self.keep_delimiter = keep;
        self
    }
}

impl FrameDelineator for DelimiterDelineator {
    fn extract_frames(&mut self, buffer: &mut Vec<u8>) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();

        if self.delimiter.is_empty() {
            return frames;
        }

        while let Some(pos) = buffer
            .windows(self.delimiter.len())
            .position(|window| window == self.delimiter)
        {
            let end = pos + self.delimiter.len();
            let mut extracted: Vec<u8> = buffer.drain(..end).collect();

            if !self.keep_delimiter {
                extracted.truncate(pos);
            }

            frames.push(extracted);
        }

        frames
    }
}

/// Демаркатор, отдающий любые накопленные сырые байты как отдельный кадр
#[derive(Debug, Default, Clone)]
pub struct RawChunkDelineator;

impl FrameDelineator for RawChunkDelineator {
    fn extract_frames(&mut self, buffer: &mut Vec<u8>) -> Vec<Vec<u8>> {
        if buffer.is_empty() {
            Vec::new()
        } else {
            vec![std::mem::take(buffer)]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_length_prefixed_delineator_u32_le() {
        let mut delineator = LengthPrefixedDelineator::new(4, Endianness::LittleEndian);

        let mut stream = Vec::new();
        // Кадр 1: длина 5 ("HELLO"), payload "HELLO"
        stream.extend_from_slice(&(5u32).to_le_bytes());
        stream.extend_from_slice(b"HELLO");

        // Кадр 2 (половина): длина 4 ("PING"), пришли только 2 байта payload
        stream.extend_from_slice(&(4u32).to_le_bytes());
        stream.extend_from_slice(b"PI");

        let frames = delineator.extract_frames(&mut stream);
        assert_eq!(frames.len(), 1);
        assert_eq!(&frames[0][4..], b"HELLO");

        // Досылаем остаток второго кадра ("NG")
        stream.extend_from_slice(b"NG");
        let frames2 = delineator.extract_frames(&mut stream);
        assert_eq!(frames2.len(), 1);
        assert_eq!(&frames2[0][4..], b"PING");
        assert!(stream.is_empty());
    }

    #[test]
    fn test_delimiter_delineator_newlines() {
        let mut delineator = DelimiterDelineator::new(b"\n").with_keep_delimiter(false);

        let mut stream = b"LINE1\nLINE2\nPARTIAL".to_vec();
        let frames = delineator.extract_frames(&mut stream);

        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0], b"LINE1");
        assert_eq!(frames[1], b"LINE2");
        assert_eq!(stream, b"PARTIAL");

        stream.extend_from_slice(b"_END\n");
        let frames2 = delineator.extract_frames(&mut stream);
        assert_eq!(frames2.len(), 1);
        assert_eq!(frames2[0], b"PARTIAL_END");
        assert!(stream.is_empty());
    }
}
