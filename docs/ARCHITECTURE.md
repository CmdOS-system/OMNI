# Arquitectura OMNI

OMNI es un gestor de compatibilidad multiplataforma. Su código, documentación y pruebas activas deben referirse exclusivamente a OMNI.

Las ejecuciones antiguas de GitHub Actions y las ramas históricas pueden conservar nombres anteriores; no representan funciones ni resultados actuales de OMNI.

## Implementado

- Inspector de formatos y despachador Linux en `engine/loader`.
- Contrato antisimulación de pruebas reales.
- Workflow de pruebas unitarias, sin certificar compatibilidad.

## Pendiente

- Integrar fuentes verificadas de Research Lab v0.12.
- Detectar motores reales (Wine, Proton/UMU, FEX, Box64, QEMU, Waydroid, Darling y Wasmtime).
- Crear Omni Planner, Execution Witness y aplicación instalable.
- Ejecutar y verificar aplicaciones de terceros en máquinas virtuales desechables.

`--register-binfmt` modifica la configuración Linux del anfitrión y no debe ejecutarse en CI. No ejecutar instaladores desconocidos sin aislamiento.
