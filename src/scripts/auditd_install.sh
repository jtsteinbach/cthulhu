sudo apt update
sudo apt install -y auditd audispd-plugins

sudo systemctl enable auditd
sudo systemctl restart auditd
