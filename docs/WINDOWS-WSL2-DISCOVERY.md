# OMNI Windows — WSL2 discovery integration

OMNI's Windows desktop now includes a Detectar motor Linux (WSL2) action.
It calls only wsl.exe --list --verbose with a 6-second timeout and no shell,
then shows installed WSL2 distribution names and whether a selected ELF
matches the host architecture. It does not start any Linux application,
install or configure a distribution, or grant execution permission.

WSL2 discovery is not proof that an ELF will run successfully. It is not
an isolation/sandbox certification. preflight_candidate is intentionally
separate from launch_available (always false for this adapter).

The probe runs on a background thread to keep the desktop responsive.
Output may be UTF-16LE (common for redirected wsl.exe output) or UTF-8.
The parser uses aligned columns and does not depend on localized column
headings or state names. Unknown output fails closed (no WSL2 candidate).

Test locally with:
python -m unittest discover -s tests -p test_wsl2_discovery.py -v

Future work: explicit WSL2 distribution selection, controlled file staging,
launch authorization and lifecycle management, then real Windows host tests.
