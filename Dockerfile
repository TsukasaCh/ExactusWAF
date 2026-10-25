# escape=`
# =====================================================================
#  ExactusWAF - image Docker (Windows container, Windows Server 2025)
#
#  Docker di server ini berjalan dalam mode Windows container, jadi
#  base image-nya Nano Server ltsc2025 (versinya harus cocok dengan host).
#
#  Cara pakai:  docker compose up -d --build
# =====================================================================

# ---- Tahap 1: compile exactuswaf.exe ----
FROM golang:1.27.3-nanoserver-ltsc2025 AS build
USER ContainerAdministrator
ENV CGO_ENABLED=0
WORKDIR C:\src
COPY go.mod go.sum .\
RUN go mod download
COPY main.go .\
COPY internal .\internal
RUN go build -trimpath -ldflags="-s -w" -o C:\out\exactuswaf.exe .

# ---- Tahap 2: image akhir yang kecil, tanpa toolchain Go ----
FROM mcr.microsoft.com/windows/nanoserver:ltsc2025
COPY --from=build C:\out\exactuswaf.exe C:\app\exactuswaf.exe
# Konfigurasi ikut masuk image. Sengaja tidak di-bind-mount: ContainerUser
# tidak diizinkan membaca folder di profil user host (Access is denied).
# Setelah mengubah docker\config.yaml, jalankan: docker compose up -d --build
COPY docker\config.yaml C:\config\config.yaml
# Folder data untuk Web ACL (dipetakan ke volume), bisa ditulis ContainerUser.
RUN mkdir C:\data && icacls C:\data /grant "Users:(OI)(CI)F"
VOLUME C:\data
WORKDIR C:\app
USER ContainerUser
EXPOSE 8080 9090
ENTRYPOINT ["C:\\app\\exactuswaf.exe", "-config", "C:\\config\\config.yaml"]
