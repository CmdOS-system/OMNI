Bubblewrap experimental boundary probe

Run: python3 -m omni.bwrap_probe

Only a fixed shell command runs, never user-provided applications. BOUNDARY_OBSERVED proves solely that the private marker was not visible in that test. Network denial, resource enforcement and full sandbox security remain unverified. Execution authorization always remains false. GitHub-hosted runners may disallow user namespaces, so BLOCKED is an acceptable fail-closed result.

CI now requires BOUNDARY_OBSERVED; a blocked probe fails the isolation test instead of silently passing.
