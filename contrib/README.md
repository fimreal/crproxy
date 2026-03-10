# Service Configuration Guide

This directory contains service configuration files for running crproxy as a system service.

## systemd (Ubuntu, Debian, CentOS, Fedora, etc.)

### Installation

1. Copy the service file:
   ```bash
   sudo cp contrib/crproxy.service /etc/systemd/system/
   ```

2. Copy the environment file:
   ```bash
   sudo mkdir -p /etc/crproxy
   sudo cp contrib/crproxy.env /etc/crproxy/crproxy.env
   sudo chmod 600 /etc/crproxy/crproxy.env
   ```

3. Edit the environment file and set your admin password:
   ```bash
   sudo nano /etc/crproxy/crproxy.env
   # Set ADMIN_PASSWORD=your_secure_password_here
   ```

4. Create crproxy user and directories:
   ```bash
   sudo useradd -r -s /bin/false crproxy
   sudo mkdir -p /var/lib/crproxy/cache
   sudo chown -R crproxy:crproxy /var/lib/crproxy
   ```

5. Copy the binary:
   ```bash
   sudo cp bin/crproxy /usr/local/bin/
   sudo chmod +x /usr/local/bin/crproxy
   ```

6. Enable and start the service:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable crproxy
   sudo systemctl start crproxy
   ```

### Management Commands

```bash
# Check status
sudo systemctl status crproxy

# View logs
sudo journalctl -u crproxy -f

# Restart service
sudo systemctl restart crproxy

# Stop service
sudo systemctl stop crproxy
```

## OpenRC (Alpine Linux, Gentoo, etc.)

### Installation

1. Copy the init script:
   ```bash
   sudo cp contrib/crproxy.initd /etc/init.d/crproxy
   sudo chmod +x /etc/init.d/crproxy
   ```

2. Copy the configuration file:
   ```bash
   sudo cp contrib/crproxy.confd /etc/conf.d/crproxy
   sudo chmod 600 /etc/conf.d/crproxy
   ```

3. Edit the configuration file and set your admin password:
   ```bash
   sudo nano /etc/conf.d/crproxy
   # Set ADMIN_PASSWORD="your_secure_password_here"
   ```

4. Create crproxy user and directories:
   ```bash
   sudo adduser -D -S -s /bin/false crproxy
   sudo mkdir -p /var/lib/crproxy/cache
   sudo chown -R crproxy:crproxy /var/lib/crproxy
   ```

5. Copy the binary:
   ```bash
   sudo cp bin/crproxy /usr/local/bin/
   sudo chmod +x /usr/local/bin/crproxy
   ```

6. Enable and start the service:
   ```bash
   sudo rc-update add crproxy default
   sudo rc-service crproxy start
   ```

### Management Commands

```bash
# Check status
sudo rc-service crproxy status

# View logs (if using syslog)
sudo tail -f /var/log/messages | grep crproxy

# Restart service
sudo rc-service crproxy restart

# Stop service
sudo rc-service crproxy stop
```

## Docker Alternative

If you prefer running with Docker, use the provided Dockerfile:

```bash
# Build image
docker build -t crproxy:latest .

# Run container
docker run -d \
  --name crproxy \
  --restart unless-stopped \
  -p 5000:5000 \
  -e ADMIN_PASSWORD=your_secure_password \
  -v /var/lib/crproxy/cache:/cache \
  -v /etc/crproxy:/etc/crproxy \
  crproxy:latest
```

## Security Recommendations

1. **Strong Password**: Generate a strong admin password:
   ```bash
   openssl rand -base64 32
   ```

2. **File Permissions**: Ensure sensitive files have restricted permissions:
   ```bash
   sudo chmod 600 /etc/crproxy/crproxy.env
   sudo chown crproxy:crproxy /etc/crproxy/crproxy.env
   ```

3. **Firewall**: Restrict access to the admin interface:
   ```bash
   # Only allow localhost access to admin interface
   sudo ufw allow 5000/tcp
   sudo ufw enable
   ```

4. **Reverse Proxy**: Consider using nginx or Caddy as a reverse proxy with TLS:
   ```nginx
   server {
       listen 443 ssl;
       server_name registry.yourdomain.com;

       ssl_certificate /path/to/cert.pem;
       ssl_certificate_key /path/to/key.pem;

       location / {
           proxy_pass http://localhost:5000;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
       }
   }
   ```

## Configuration Files

- **systemd**: `crproxy.service`, `crproxy.env`
- **OpenRC**: `crproxy.initd`, `crproxy.confd`

## Troubleshooting

### Service won't start

1. Check logs:
   ```bash
   # systemd
   sudo journalctl -u crproxy -n 50

   # OpenRC
   sudo tail -f /var/log/messages
   ```

2. Verify permissions:
   ```bash
   ls -la /var/lib/crproxy
   ls -la /etc/crproxy
   ```

3. Test manually:
   ```bash
   sudo -u crproxy /usr/local/bin/crproxy -listen :5000 -cache-dir /var/lib/crproxy/cache
   ```

### Admin interface not accessible

1. Verify `ADMIN_PASSWORD` is set in the environment file
2. Check the service is running: `sudo systemctl status crproxy`
3. Test the endpoint: `curl http://localhost:5000/admin`

### Cache issues

1. Check cache directory permissions:
   ```bash
   ls -la /var/lib/crproxy/cache
   ```

2. Clear cache if needed:
   ```bash
   sudo rm -rf /var/lib/crproxy/cache/*
   sudo systemctl restart crproxy
   ```
