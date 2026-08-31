# poc_container_escape

**Enumeración y explotación de vectores de escape de contenedores Docker / Kubernetes / LXC.**

> ⚠️ **Aviso legal** — Herramienta destinada exclusivamente a pentestings y auditorías de seguridad en contenedores **autorizados**. El autor no se hace responsable del uso indebido.

---

## Qué hace

El script detecta si se ejecuta dentro de un contenedor y evalúa **7 vectores de escape** conocidos, reportando cuáles son explotables:

| # | Vector | Qué comprueba |
|---|--------|---------------|
| 1 | **Contenedor privilegiado** | Escritura en `release_agent` del cgroup |
| 2 | **Docker socket montado** | Acceso a `/var/run/docker.sock` |
| 3 | **Host filesystem expuesto** | Montajes hostPath / discos del host visibles |
| 4 | **Capacidades peligrosas** | `CAP_SYS_ADMIN`, `CAP_DAC_READ_SEARCH` |
| 5 | **PID namespace compartido** | Procesos del host visibles (hostPID) |
| 6 | **Credenciales reutilizables** | SSH keys, K8s service account tokens |
| 7 | **Kernel / CVEs conocidos** | Versión del kernel vs DirtyPipe, runc CVE-2019-5736 |

Si un vector es explotable, el script intenta una **demo de explotación mínima** (ej. listar archivos del host, leer shadow) y deja artefactos en `/tmp/.escape_poc_$$`.

---

## Requisitos

- Bash (sin dependencias externas; `curl` y `capsh` son opcionales)
- Ejecutar **dentro** de un contenedor (Docker, K8s, LXC…)
- Permisos de lectura sobre `/proc`, `/sys` y `/proc/mounts`

---

## Uso

```bash
chmod +x poc_container_escape.sh
./poc_container_escape.sh
```

**Ejemplo de salida esperada** (contenedor Docker sin privilegios):

```
==============================================
 Enumeracion de escape de contenedor - a1b2c3d4e5f6
==============================================
[+] /.dockerenv presente: estamos en Docker
[+] cgroups del PID 1 apuntan a un contenedor: 0::/docker/...

---------- Contexto ----------
[*] Usuario actual: uid=0(root) gid=0(root) groups=0(root)
[*] Kernel: 5.15.0-78-generic
[*] Mounts interesantes:
overlay on / type overlay (rw,relatime,upperdir=...)

---------- Chequeo de vectores de escape ----------
[-] release_agent no escribible (contenedor sin privilegios)
[-] docker.sock no presente

==============================================
 Resumen
==============================================
[*] Artefactos recolectados en: /tmp/.escape_poc_1234
```

---

## Qué hacer después (si se detecta un vector explotable)

1. **Escritura en hostPath / release_agent** → inyectar tu clave pública SSH en `~/.ssh/authorized_keys` del host y conectar vía SSH.
2. **Docker socket** → lanzar un contenedor con `-v /:/host --privileged` y `chroot /host`.
3. **hostPID** → `nsenter -t <PID> -m -u -i -n -p` para caer en el namespace del host.
4. **CAP_SYS_ADMIN** → montar un overlay o namespace para romper el sandbox.

---

## Estructura

```
.
├── README.md
└── poc_container_escape.sh
```

---

## Licencia

MIT — usar bajo tu propia responsabilidad y con autorización.
