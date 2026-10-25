//! Bounded structural inspection for APK and CRX containers.
//! This module parses metadata only; it never extracts archive paths to disk.

fn u16le(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}

fn u32le(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

fn string_length(bytes: &[u8], at: usize) -> Option<(usize, usize)> {
    let first = *bytes.get(at)?;
    if first & 0x80 == 0 {
        Some((first as usize, at + 1))
    } else {
        let second = *bytes.get(at + 1)?;
        Some((((first as usize & 0x7f) << 8) | second as usize, at + 2))
    }
}

fn parse_string_pool(bytes: &[u8], at: usize, size: usize) -> Option<Vec<String>> {
    if u16le(bytes, at)? != 0x0001 || u16le(bytes, at + 2)? < 28 {
        return None;
    }
    let string_count = u32le(bytes, at + 8)? as usize;
    if string_count > 65_536 {
        return None;
    }
    let flags = u32le(bytes, at + 16)?;
    let strings_start = u32le(bytes, at + 20)? as usize;
    let offsets_start = at.checked_add(u16le(bytes, at + 2)? as usize)?;
    let chunk_end = at.checked_add(size)?;
    if offsets_start.checked_add(string_count.checked_mul(4)?)? > chunk_end {
        return None;
    }
    let mut strings = Vec::with_capacity(string_count);
    for index in 0..string_count {
        let offset = u32le(bytes, offsets_start + index * 4)? as usize;
        let mut cursor = at.checked_add(strings_start)?.checked_add(offset)?;
        if cursor >= chunk_end {
            return None;
        }
        if flags & 0x100 != 0 {
            let (_, next) = string_length(bytes, cursor)?;
            cursor = next;
            let (byte_len, next) = string_length(bytes, cursor)?;
            cursor = next;
            let raw = bytes.get(cursor..cursor.checked_add(byte_len)?)?;
            if cursor + byte_len >= chunk_end {
                return None;
            }
            if bytes.get(cursor + byte_len) != Some(&0) {
                return None;
            }
            strings.push(std::str::from_utf8(raw).ok()?.to_owned());
        } else {
            let (utf16_len, next) = string_length(bytes, cursor)?;
            cursor = next;
            let byte_len = utf16_len.checked_mul(2)?;
            if cursor.checked_add(byte_len)?.checked_add(2)? > chunk_end {
                return None;
            }
            let raw = bytes.get(cursor..cursor.checked_add(byte_len)?)?;
            if u16::from_le_bytes(bytes.get(cursor + byte_len..cursor + byte_len + 2)?.try_into().ok()?) != 0 {
                return None;
            }
            let units = raw.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]]));
            strings.push(char::decode_utf16(units).collect::<Result<String, _>>().ok()?);
        }
    }
    Some(strings)
}

/// Reads a package ID from Android's binary XML manifest (AXML).
pub fn android_package_id(manifest: &[u8]) -> Result<String, &'static str> {
    if manifest.len() < 8 || u16le(manifest, 0) != Some(0x0003) {
        return Err("AndroidManifest.xml no tiene cabecera AXML válida");
    }
    let document_size = u32le(manifest, 4).ok_or("AXML truncado")? as usize;
    if document_size < 8 || document_size > manifest.len() || document_size > 4 * 1024 * 1024 {
        return Err("Tamaño AXML fuera del límite permitido");
    }
    let mut cursor = u16le(manifest, 2).ok_or("AXML truncado")? as usize;
    if cursor < 8 || cursor > document_size {
        return Err("Cabecera AXML inválida");
    }
    let mut strings: Option<Vec<String>> = None;
    while cursor + 8 <= document_size {
        let kind = u16le(manifest, cursor).ok_or("Chunk AXML truncado")?;
        let header_size = u16le(manifest, cursor + 2).ok_or("Chunk AXML truncado")? as usize;
        let chunk_size = u32le(manifest, cursor + 4).ok_or("Chunk AXML truncado")? as usize;
        let end = cursor.checked_add(chunk_size).ok_or("Tamaño de chunk AXML desbordado")?;
        if header_size < 8 || chunk_size < header_size || end > document_size {
            return Err("Límites de chunk AXML inválidos");
        }
        if kind == 0x0001 {
            strings = Some(parse_string_pool(manifest, cursor, chunk_size).ok_or("String pool AXML inválido")?);
        } else if kind == 0x0102 {
            let pool = strings.as_ref().ok_or("AXML no contiene string pool antes del manifiesto")?;
            let node_name_index = u32le(manifest, cursor + 20).ok_or("Nodo AXML truncado")? as usize;
            if pool.get(node_name_index).map(String::as_str) == Some("manifest") {
                let ext = cursor + 16;
                let attribute_start = u16le(manifest, ext + 8).ok_or("Atributos AXML truncados")? as usize;
                let attribute_size = u16le(manifest, ext + 10).ok_or("Atributos AXML truncados")? as usize;
                let attribute_count = u16le(manifest, ext + 12).ok_or("Atributos AXML truncados")? as usize;
                if attribute_start < 20 || attribute_size < 20 || attribute_count > 1024 {
                    return Err("Tabla de atributos AXML inválida");
                }
                let mut attribute = ext.checked_add(attribute_start).ok_or("Offset de atributo desbordado")?;
                for _ in 0..attribute_count {
                    let attribute_end = attribute.checked_add(attribute_size).ok_or("Atributo AXML desbordado")?;
                    if attribute_end > end {
                        return Err("Atributo AXML fuera del manifiesto");
                    }
                    let name = u32le(manifest, attribute + 4).ok_or("Atributo AXML truncado")? as usize;
                    let raw_value = u32le(manifest, attribute + 8).ok_or("Atributo AXML truncado")?;
                    let typed_kind = *manifest.get(attribute + 15).ok_or("Valor AXML truncado")?;
                    let typed_value = u32le(manifest, attribute + 16).ok_or("Valor AXML truncado")?;
                    if pool.get(name).map(String::as_str) == Some("package") {
                        let value = if raw_value != u32::MAX {
                            pool.get(raw_value as usize)
                        } else if typed_kind == 0x03 {
                            pool.get(typed_value as usize)
                        } else {
                            None
                        }.ok_or("El atributo package no contiene una cadena")?;
                        if value.is_empty() || !value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_') {
                            return Err("El ID de paquete Android contiene caracteres no permitidos");
                        }
                        return Ok(value.clone());
                    }
                    attribute = attribute_end;
                }
            }
        }
        cursor = end;
    }
    Err("No se encontró package en AndroidManifest.xml")
}

pub fn valid_dex_header(bytes: &[u8]) -> bool {
    if bytes.len() < 112
        || !bytes.starts_with(b"dex\n")
        || !bytes[4..7].iter().all(u8::is_ascii_digit)
        || bytes[7] != 0
    {
        return false;
    }
    let file_size = u32le(bytes, 32).unwrap_or(0) as usize;
    let header_size = u32le(bytes, 36).unwrap_or(0);
    let endian_tag = u32le(bytes, 40).unwrap_or(0);
    (112..=512 * 1024 * 1024).contains(&file_size)
        && header_size == 112
        && endian_tag == 0x1234_5678
}

/// Returns the ZIP payload offset for CRX v2/v3 after checking header bounds.
pub fn crx_zip_offset(header: &[u8]) -> Result<usize, &'static str> {
    if header.len() < 12 || !header.starts_with(b"Cr24") {
        return Err("Cabecera CRX ausente o truncada");
    }
    let version = u32le(header, 4).ok_or("Cabecera CRX truncada")?;
    let offset = match version {
        2 => {
            let public_key = u32le(header, 8).ok_or("Longitud CRX2 truncada")? as usize;
            let signature_at = 12usize.checked_add(public_key).ok_or("Longitud CRX2 desbordada")?;
            let signature = u32le(header, signature_at).ok_or("Firma CRX2 truncada")? as usize;
            if public_key == 0 || signature == 0 {
                return Err("CRX2 requiere clave pública y firma no vacías");
            }
            signature_at.checked_add(4).and_then(|n| n.checked_add(signature)).ok_or("Longitud CRX2 desbordada")?
        }
        3 => {
            let header_size = u32le(header, 8).ok_or("Longitud CRX3 truncada")? as usize;
            if header_size == 0 || header_size > 1024 * 1024 {
                return Err("Longitud de cabecera CRX3 fuera de rango");
            }
            12usize.checked_add(header_size).ok_or("Longitud CRX3 desbordada")?
        }
        _ => return Err("Versión CRX no soportada; solo CRX2 y CRX3"),
    };
    if offset >= header.len() {
        return Err("El paquete CRX no contiene datos ZIP después de la cabecera");
    }
    Ok(offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_complete_dex_magic_and_versions() {
        let mut dex = vec![0u8; 112];
        dex[..8].copy_from_slice(b"dex\n035\0");
        dex[32..36].copy_from_slice(&128u32.to_le_bytes());
        dex[36..40].copy_from_slice(&112u32.to_le_bytes());
        dex[40..44].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        assert!(valid_dex_header(&dex));
        dex[36..40].copy_from_slice(&0u32.to_le_bytes());
        assert!(!valid_dex_header(&dex));
        assert!(!valid_dex_header(b"dex\nabc\0"));
        assert!(!valid_dex_header(b"dex"));
    }

    #[test]
    fn validates_crx2_and_crx3_bounds() {
        assert_eq!(crx_zip_offset(b"Cr24\x03\0\0\0\x04\0\0\0hdrZIP").unwrap(), 16);
        assert_eq!(crx_zip_offset(b"Cr24\x03\0\0\0\xff\xff\xff\xff"), Err("Longitud de cabecera CRX3 fuera de rango"));
        assert!(crx_zip_offset(b"Cr24\x04\0\0\0\0\0\0\0ZIP").is_err());
    }

    #[test]
    fn parses_binary_android_manifest_package_id() {
        let bytes = include_bytes!("../tests/fixtures/minimal-manifest.axml");
        assert_eq!(android_package_id(bytes).unwrap(), "com.example.omni.smoke");
        assert!(android_package_id(b"<manifest package='bad'/>").is_err());
    }
}
