# Contributing

1. Test only lab targets (`127.0.0.1`, RFC1918, `example.*`). Never add tests hitting public sites.
2. Keep runtime dependencies minimal (`requests` + stdlib).
3. Probes must use safe payloads and carry a timeout.
4. Run before pushing: `python3 -m py_compile *.py` and the entry point with `-h`.
5. Do not commit secrets or scan output of third-party sites.
