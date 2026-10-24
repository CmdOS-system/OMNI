//! Bounded format identification only. This module never maps or executes input.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BinaryFormat {
    Elf,
    PeCandidate,
    MachO64,
    MachOFat,
    Dex,
    ZipContainer,
    WebAssemblyCandidate,
    CrxCandidate,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Subsystem {
    LinuxAbi,
    WindowsCompatibility,
    DarwinCompatibility,
    AndroidRuntime,
    WasmRuntime,
    ChromeExtensionManager,
    ContainerInspector,
    None,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Detection {
    pub format: BinaryFormat,
    pub subsystem: Subsystem,
    pub note: &'static str,
}

const UNKNOWN: Detection = Detection {
    format: BinaryFormat::Unknown,
    subsystem: Subsystem::None,
    note: "No se reconoce la firma; no ejecutar el archivo.",
};

/// Inspects a prefix supplied by a bounded file reader; extensions are ignored.
pub fn detect_magic(bytes: &[u8]) -> Detection {
    if bytes.starts_with(b"\0asm") {
        return Detection {
            format: BinaryFormat::WebAssemblyCandidate,
            subsystem: Subsystem::WasmRuntime,
            note: "Firma WebAssembly reconocida; validar versión, secciones, imports y límites antes de ejecutar en un runtime WASI aislado.",
        };
    }

    if bytes.starts_with(b"Cr24") {
        return Detection {
            format: BinaryFormat::CrxCandidate,
            subsystem: Subsystem::ChromeExtensionManager,
            note: "Cabecera CRX reconocida; comprobar versión y longitudes, verificar firma/publicador y permisos antes de instalar.",
        };
    }

    if bytes.starts_with(b"\x7fELF") {
        return Detection {
            format: BinaryFormat::Elf,
            subsystem: Subsystem::LinuxAbi,
            note: "Cabecera ELF reconocida; validar clase, arquitectura, segmentos y ABI antes de cargar.",
        };
    }

    if bytes.starts_with(b"MZ") {
        return Detection {
            format: BinaryFormat::PeCandidate,
            subsystem: Subsystem::WindowsCompatibility,
            note: "Candidato DOS/PE; localizar y validar PE\0\0 y límites de secciones antes de usar Windows bridge.",
        };
    }

    if bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xcf])
        || bytes.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
    {
        return Detection {
            format: BinaryFormat::MachO64,
            subsystem: Subsystem::DarwinCompatibility,
            note: "Mach-O de 64 bits reconocido; validar endian, CPU, firma y dependencias Darwin.",
        };
    }

    if bytes.starts_with(&[0xca, 0xfe, 0xba, 0xbe])
        || bytes.starts_with(&[0xbe, 0xba, 0xfe, 0xca])
    {
        return Detection {
            format: BinaryFormat::MachOFat,
            subsystem: Subsystem::DarwinCompatibility,
            note: "Contenedor Mach-O universal candidato; validar cada slice y límites.",
        };
    }

    if bytes.len() >= 8
        && bytes.starts_with(b"dex\n")
        && bytes[4..7].iter().all(u8::is_ascii_digit)
        && bytes[7] == 0
    {
        return Detection {
            format: BinaryFormat::Dex,
            subsystem: Subsystem::AndroidRuntime,
            note: "DEX reconocido; requiere ART/Dalvik y framework Android compatible.",
        };
    }

    if bytes.starts_with(b"PK\x03\x04") {
        return Detection {
            format: BinaryFormat::ZipContainer,
            subsystem: Subsystem::ContainerInspector,
            note: "ZIP reconocido; no asumir que es APK. Validar directorio central, AndroidManifest.xml y contenido antes de activar ART.",
        };
    }

    UNKNOWN
}

/// APK is a ZIP container, not a DEX magic header. Call only after a bounded,
/// traversal-safe ZIP parser has listed entries without extracting them.
pub fn classify_zip_entries<'a>(entries: impl IntoIterator<Item = &'a str>) -> Detection {
    let mut manifest = false;
    let mut payload = false;
    for entry in entries {
        if entry == "AndroidManifest.xml" {
            manifest = true;
        }
        if entry == "classes.dex" || entry.starts_with("classes") && entry.ends_with(".dex")
            || entry.starts_with("lib/")
        {
            payload = true;
        }
    }
    if manifest && payload {
        Detection {
            format: BinaryFormat::ZipContainer,
            subsystem: Subsystem::AndroidRuntime,
            note: "Estructura APK básica reconocida; verificar firma, manifiesto, ABI nativa y permisos.",
        }
    } else {
        Detection {
            format: BinaryFormat::ZipContainer,
            subsystem: Subsystem::None,
            note: "ZIP sin estructura APK básica confirmada.",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_elf_pe_macho_dex_and_zip_by_magic() {
        assert_eq!(detect_magic(b"\x7fELF\x02").format, BinaryFormat::Elf);
        assert_eq!(detect_magic(b"MZ\x00\x00").format, BinaryFormat::PeCandidate);
        assert_eq!(detect_magic(&[0xfe, 0xed, 0xfa, 0xcf]).format, BinaryFormat::MachO64);
        assert_eq!(detect_magic(&[0xcf, 0xfa, 0xed, 0xfe]).format, BinaryFormat::MachO64);
        assert_eq!(detect_magic(&[0xca, 0xfe, 0xba, 0xbe]).format, BinaryFormat::MachOFat);
        assert_eq!(detect_magic(b"dex\n035\0").format, BinaryFormat::Dex);
        assert_eq!(detect_magic(b"PK\x03\x04").format, BinaryFormat::ZipContainer);
    }

    #[test]
    fn detects_wasm_and_crx_as_unverified_candidates() {
        let wasm = detect_magic(b"\0asm\x01\0\0\0");
        assert_eq!(wasm.format, BinaryFormat::WebAssemblyCandidate);
        assert_eq!(wasm.subsystem, Subsystem::WasmRuntime);

        let crx2 = detect_magic(b"Cr24\x02\0\0\0");
        let crx3 = detect_magic(b"Cr24\x03\0\0\0");
        assert_eq!(crx2.format, BinaryFormat::CrxCandidate);
        assert_eq!(crx3.format, BinaryFormat::CrxCandidate);
        assert_eq!(crx3.subsystem, Subsystem::ChromeExtensionManager);
        assert!(crx3.note.contains("verificar firma"));
    }

    #[test]
    fn zip_is_not_mistaken_for_apk_without_android_entries() {
        let result = classify_zip_entries(["readme.txt", "bin/app"]);
        assert_eq!(result.subsystem, Subsystem::None);
    }

    #[test]
    fn apk_requires_manifest_and_dex_or_native_library() {
        assert_eq!(
            classify_zip_entries(["AndroidManifest.xml", "classes.dex"]).subsystem,
            Subsystem::AndroidRuntime
        );
        assert_eq!(
            classify_zip_entries(["AndroidManifest.xml", "lib/arm64-v8a/libx.so"]).subsystem,
            Subsystem::AndroidRuntime
        );
        assert_eq!(
            classify_zip_entries(["classes.dex"]).subsystem,
            Subsystem::None
        );
    }

    #[test]
    fn rejects_short_or_unknown_prefixes() {
        assert_eq!(detect_magic(b"dex").format, BinaryFormat::Unknown);
        assert_eq!(detect_magic(b"not an executable").subsystem, Subsystem::None);
    }
}
