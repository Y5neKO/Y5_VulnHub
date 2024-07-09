# CVE-2024-39943-Poc
CVE-2024-39943 rejetto HFS (aka HTTP File Server) 3 before 0.52.10 on Linux, UNIX, and macOS allows OS command execution by remote authenticated users (if they have Upload permissions). This occurs because a shell is used to execute df (i.e., with execSync instead of spawnSync in child_process in Node.js).

Deploy: ``` ./hfs --config config.yaml ```


https://github.com/truonghuuphuc/CVE-2024-39943-Poc/assets/20487674/c9e3d7ec-9181-43b5-8230-82c36fbf8a2b

