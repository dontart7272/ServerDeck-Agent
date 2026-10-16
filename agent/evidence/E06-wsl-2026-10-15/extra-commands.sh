set -euo pipefail
base="$HOME/serverdeck-e06-final-2026-10-15"
copy=$(cat "$base/copy-path.txt")
source "$HOME/serverdeck-e01-2026-10-13/env.sh"
cd "$copy/agent"
{
date -u --iso-8601=seconds
uname -a
id
for command in journalctl nvidia-smi nft iptables fail2ban-client docker; do command -v "$command" || true; done
for item in /usr/lib/wsl/lib/libnvidia-ml.so.1 /usr/lib/wsl/lib/nvidia-smi /dev/dxg /dev/nvidiactl /var/run/docker.sock /var/log/auth.log; do if test -e "$item"; then stat -c '%n mode=%a uid=%u gid=%g' "$item";else printf 'ABSENT %s\n' "$item";fi; done
journalctl --version | head -1
journalctl --help | grep -E -- '--(system|after-cursor|output-fields|no-tail|since)' || true
ldconfig -p | grep -E 'libnvidia-ml|libsystemd' || true
} > "$base/evidence/adapters-environment.txt"
go list -m -json all > "$base/evidence/modules.json"
go mod download -json github.com/NVIDIA/go-nvml@v0.13.4-1 > "$base/evidence/nvml-provenance.json"
go list -deps -f '{{if not .Standard}}{{.ImportPath}}{{end}}' ./cmd/serverdeck-agent > "$base/evidence/runtime-packages.txt"
{
for binary in dist/linux-{amd64,arm64}/{serverdeck-agent,serverdeckctl}; do
 printf '\nBINARY %s\n' "$binary"
 file "$binary"
 readelf -h "$binary" | grep -E 'Class:|Type:|Machine:'
 readelf -l "$binary" | grep 'program interpreter'
 readelf -d "$binary" | grep -E 'NEEDED|RPATH|RUNPATH' || true
 readelf --version-info "$binary" | grep -oE 'GLIBC_[0-9.]+' | sort -Vu
 done
} > "$base/evidence/elf.txt"
