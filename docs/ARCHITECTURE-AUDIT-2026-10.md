# OMNI — Auditoría de arquitectura y plan de evolución

Fecha: 2026-10-24. Alcance: inspección estática del árbol principal y contraste con documentación de QEMU y Bottles. No es una auditoría exhaustiva de seguridad.

## Hallazgos verificables

1. El despachador de `engine/loader/src/main.rs` tiene rutas para PE, MSI, APK, DEX, Mach-O, WASM, CRX, DEB y ELF; la detección de firma por sí sola **no prueba** que un archivo sea ejecutable ni compatible.
2. `engine/loader/src/magic_detector.rs` devuelve candidatos para formatos con cabeceras parciales. Separar reconocimiento, validación estructural, selección de motor y ejecución.
3. `vm/boot.py` utiliza `q35,accel=tcg`, desactiva red y compartición del anfitrión. **TCG no es una frontera de seguridad certificada** según QEMU. No usar estos experimentos para ejecutables no confiables.
4. `proof/verify.py` comprueba integridad y consistencia local; no prueba autenticidad, aislamiento ni que un usuario completara una tarea funcional.
5. `scripts/third_party_guest_probe.py` ejecutó GNU Hello desde el paquete de Ubuntu en QEMU (CI 40153429830), con salida y código de terminación observados. No implica compatibilidad general.
6. `docs/ARCHITECTURE.md` enumera Omni Planner, Execution Witness y la aplicación instalable como pendientes; no tratarlos como implementados.

## Riesgos y correcciones prioritarias

**P0 — Aislamiento real.** Para binarios no confiables, usar VM de confianza con KVM/HVF/WHPX cuando proceda, sin red ni carpetas compartidas por defecto, QEMU no privilegiado, restricciones de recursos y políticas del anfitrión. Bloquear si no se puede demostrar el aislamiento. No afirmar que TCG lo garantiza.

**P0 — Contrato de evidencia.** Distinguir `DETECTED`, `PREPARED`, `STARTED`, `TASK_OBSERVED_UNATTESTED`, `PASS_ATTESTED`, `FAIL`, `BLOCKED` y `NOT_RUN`. El exit code de QEMU y un marcador serial no bastan para certificar aplicaciones. Capturar versiones, SHA-256, procedencia, PID real y descendientes, acciones funcionales y artefactos.

**P1 — Planner de motores.** Crear interfaz `probe / plan / prepare / execute / collect / cleanup` para cada runtime. Selección según arquitectura, formato validado, ABI, GPU, requisitos de red y política de seguridad; prohibir rutas ficticias. Wine/Proton para PE, Linux nativo para ELF, QEMU para VM, Waydroid para Android, Wasmtime para WASM. El resultado debe explicar por qué eligió o rechazó cada motor.

**P1 — Instalación reproducible.** Registrar hashes de instaladores originales, firmas cuando existan, dependencias, prefijos aislados y cambios en el sistema. No descargar ni ejecutar instaladores de origen desconocido de manera automática.

**P1 — Pruebas reales de Wine.** Empezar con una aplicación Windows redistribuible y de licencia clara, registrar URL de procedencia, versión, hash, versión de Wine y prefijo nuevo. Verificar una acción funcional real, no solo el arranque de `wine`. Después ampliar a interfaz gráfica con evidencia de interacción.

**P2 — Experiencia de usuario.** Una interfaz con una acción primaria: abrir archivo → diagnóstico → motor recomendado → ejecutar → resultado visible. Mostrar claramente bloqueos, permisos y pruebas realizadas; no ocultar detalles de seguridad.

## Diseño propuesto

```
UI/CLI
  -> File Inspector (magic + validación profunda + SHA256)
  -> Capability Planner (runtime, arquitectura, política)
  -> Runtime Adapter (Wine / Proton / Linux / QEMU / etc.)
  -> Isolated Executor (procesos, recursos, permisos)
  -> Execution Witness (eventos + artefactos + provenance)
  -> Evidence Verifier (fail-closed)
```

## Criterios de aceptación

- Cada adapter declara capacidades reales y comandos disponibles; no inventa soporte.
- Cada ejecución produce `run_id`, origen, hash, versiones, motor, permisos, tiempos, salida, fallos y estado explícito.
- Un error de aislamiento, dependencia, timeout, hash o prueba funcional termina en `BLOCKED`/`FAIL`, nunca `PASS`.
- Las pruebas unitarias con fixtures no se contabilizan como ejecución de aplicaciones reales.
- CI diferencia claramente smoke tests, ejecución real de terceros y pruebas Windows bajo Wine.

## Fuentes

- https://www.qemu.org/docs/master/system/security.html
- https://qemu-project.gitlab.io/qemu/system/introduction.html
- https://docs.usebottles.com/components/runners
- https://github.com/bottlesdevs/Bottles

## Próxima implementación recomendada

Implementar primero el `Capability Planner` con un contrato JSON y pruebas unitarias, luego un adapter Wine con preflight y ejecución de una aplicación Windows legítima en un entorno adecuadamente aislado.
