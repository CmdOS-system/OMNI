# OMNI

OMNI es un proyecto de investigación y desarrollo de compatibilidad de aplicaciones entre sistemas operativos. Este repositorio está dedicado exclusivamente a OMNI.

## Estado comprobado

- Se conserva el código histórico del analizador OmniLoader en `engine/loader/` como punto de partida; **no constituye compatibilidad certificada**.
- El contrato de pruebas reales está en `docs/PROOF-CONTRACT.md`.
- El workflow inicial está en `.github/workflows/omni-genuine-source.yml`. Su ejecución satisfactoria no está confirmada.
- No hay pruebas verificadas aquí de ejecución funcional de aplicaciones de terceros.

## Seguridad y evidencia

No presentar simulaciones, mocks, instaladores generados por agentes ni pruebas unitarias como ejecución auténtica de aplicaciones externas. Los estados de compatibilidad requieren evidencia independiente. Nunca ejecutar instaladores desconocidos sin aislamiento.

## Historial

El commit anterior de la rama principal conserva la historia del antiguo proyecto. El árbol actual contiene solamente archivos de OMNI. La migración de los prototipos Research Lab v0.1–v0.12 todavía está pendiente; no se afirma que estén integrados.
