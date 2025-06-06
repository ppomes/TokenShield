# TokenShield Debian Packaging

This directory contains the Debian packaging files for TokenShield components.

## Packages

### tokenshield-unified
The main tokenization service that provides:
- HTTP tokenization server (port 8080)
- ICAP detokenization server (port 1344)
- REST management API (port 8090)

### tokenshield-cli
Command-line interface for managing TokenShield:
- Token management
- API key operations
- Activity monitoring
- System statistics

## Building Packages

### Prerequisites

Install required build tools:
```bash
sudo apt-get update
sudo apt-get install build-essential devscripts lintian golang-go
```

### Build Process

From the TokenShield root directory:
```bash
./debian/build-packages.sh
```

This will create both .deb packages in the `build/` directory.

### Manual Build

To build packages manually:

```bash
# For tokenshield-unified
cd build/tokenshield-unified
dpkg-buildpackage -us -uc -b

# For tokenshield-cli
cd build/tokenshield-cli
dpkg-buildpackage -us -uc -b
```

## Installation

### Install Packages
```bash
sudo dpkg -i build/tokenshield-unified_*.deb
sudo dpkg -i build/tokenshield-cli_*.deb
```

### Fix Dependencies
If there are dependency issues:
```bash
sudo apt-get install -f
```

### Configure and Start Service

1. Edit configuration:
```bash
sudo nano /etc/default/tokenshield-unified
```

2. Start the service:
```bash
sudo systemctl start tokenshield-unified
sudo systemctl enable tokenshield-unified
```

3. Check status:
```bash
sudo systemctl status tokenshield-unified
```

## Configuration

### Service Configuration
- Main config: `/etc/default/tokenshield-unified`
- Logs: `/var/log/tokenshield/`
- Data: `/var/lib/tokenshield/`

### CLI Configuration
- User config: `~/.config/tokenshield/config.yaml`
- System config: `/etc/tokenshield/tokenshield.conf`

## Uninstallation

### Remove Packages
```bash
sudo apt-get remove tokenshield-unified tokenshield-cli
```

### Purge (remove configuration and data)
```bash
sudo apt-get purge tokenshield-unified tokenshield-cli
```

## Package Contents

### tokenshield-unified
- `/usr/bin/tokenshield-unified` - Main binary
- `/lib/systemd/system/tokenshield-unified.service` - Systemd service
- `/etc/default/tokenshield-unified` - Default configuration
- `/var/log/tokenshield/` - Log directory
- `/var/lib/tokenshield/` - Data directory

### tokenshield-cli
- `/usr/bin/tokenshield` - CLI binary
- `/usr/share/bash-completion/completions/tokenshield` - Bash completion
- `/usr/share/zsh/vendor-completions/_tokenshield` - Zsh completion
- `/usr/share/man/man1/tokenshield.1` - Man page
- `/etc/tokenshield/tokenshield.conf.example` - Example configuration

## Development

### Testing Packages
Use lintian to check for packaging issues:
```bash
lintian build/tokenshield-unified_*.deb
lintian build/tokenshield-cli_*.deb
```

### Version Updates
Update version in:
- `debian/tokenshield-unified/changelog`
- `debian/tokenshield-cli/changelog`
- Build scripts in `rules` files

## Security Considerations

The tokenshield-unified service runs as a dedicated user with:
- Restricted file system access
- No shell access
- Limited system call permissions
- Private temp directory
- Read-only system directories

## Support

For issues or questions:
- GitHub: https://github.com/ppomes/TokenShield
- Email: pierre.pomes@gmail.com