#!/bin/bash
set -e

echo "Creating CT scanner service at /etc/ct-scanner"

mkdir /etc/ct-scanner
cp systemd_unit_file.service /etc/systemd/system/ct-scanner.service
cp starter.sh /etc/ct-scanner/
go build -o scanlog/scanlog scanlog/scanlog.go
cp scanlog/scanlog /etc/ct-scanner
cp logs.latest.csv /etc/ct-scanner
systemctl enable ct-scanner

echo "DONE. You can start the service by typing 'systemctl start ct-scanner'"