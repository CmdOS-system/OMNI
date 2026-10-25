# OMNI

Repositorio exclusivo del proyecto OMNI: gestor de compatibilidad multiplataforma en investigación.

## Componentes

- `engine/loader/`: inspector y despachador Rust actualmente orientado a Linux.
- `docs/PROOF-CONTRACT.md`: verificación de aplicaciones reales.
- `docs/ARCHITECTURE.md`: arquitectura y alcance.

## Pruebas

`cargo test --workspace --all-targets`

No se ha certificado ninguna aplicación externa. La aplicación instalable y la migración de Research Lab v0.12 siguen pendientes.

## Windows Preview (experimental)

El ejecutable de Windows se genera mediante el workflow `OMNI Windows Preview executable`.
Su biblioteca muestra, en segundo plano, el estado de integridad de los archivos
registrados: **Sin cambios**, **Modificado**, **No encontrado** o **No disponible**.
La comprobación se repite al añadir o quitar archivos y se puede solicitar
manualmente con **Verificar archivo**. Los resultados son observaciones puntuales:
**no certifican compatibilidad ni seguridad**, no ejecutan aplicaciones y no
actualizan la huella SHA-256 guardada. Los motores de ejecución vuelven a
comprobar el archivo antes de iniciarlo y solicitan confirmación explícita.
