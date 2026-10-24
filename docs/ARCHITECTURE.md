# Arquitectura OMNI

OMNI no es Nexus OS. Es un gestor de compatibilidad multiplataforma.

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
