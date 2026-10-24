# OMNI

Repositorio exclusivo del proyecto OMNI: gestor de compatibilidad multiplataforma en investigación.

## Componentes

- `engine/loader/`: inspector y despachador Rust actualmente orientado a Linux.
- `docs/PROOF-CONTRACT.md`: verificación de aplicaciones reales.
- `docs/ARCHITECTURE.md`: arquitectura y alcance.

## Pruebas

`cargo test --workspace --all-targets`

No se ha certificado ninguna aplicación externa. La aplicación instalable y la migración de Research Lab v0.12 siguen pendientes.
