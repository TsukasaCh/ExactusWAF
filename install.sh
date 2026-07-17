#!/usr/bin/env bash
# =====================================================================
#  ExactusWAF - Installer untuk Linux / macOS
#  Pemakaian:  bash install.sh
# =====================================================================
set -e
cd "$(dirname "$0")"

echo ""
echo "  ==> ExactusWAF Installer"
echo ""

if ! command -v go >/dev/null 2>&1; then
  echo "  [!] Go belum terpasang."
  echo "      Ubuntu/Debian : sudo apt install golang-go"
  echo "      macOS (brew)  : brew install go"
  echo "      Atau unduh    : https://go.dev/dl/"
  exit 1
fi

echo "  [1/2] Mengunduh dependensi..."
go mod tidy

echo "  [2/2] Membangun binary 'exactuswaf'..."
go build -o exactuswaf .

echo ""
echo "  [OK] Selesai! Jalankan dengan:"
echo "       ./exactuswaf"
echo ""
echo "  Tips: edit config.yaml dulu untuk mengarahkan 'backend' ke website Anda."
echo ""
