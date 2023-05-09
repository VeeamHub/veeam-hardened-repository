# Veeam Hardened Linux Repository

This linux script can be used to apply hardening settings based on DISA STIG to [Veeam Hardened Linux Repository](https://helpcenter.veeam.com/docs/backup/vsphere/hardened_repository.html?ver=120). Download and run it on fresh Ubuntu 20.04 installation.

This tool is community supported and not an officially supported Veeam product.

## 📗 Documentation

**System Requirements:**

- Must be run as elevated user
- Must be run on fresh Ubuntu 20.04 installation

**Operation:**

1. Connect through SSH to fresh Ubuntu 20.04 server installation
2. Copy script to that server.
3. Run the script with the following command:
```bash
sudo bash veeam.harden.sh > output.txt 2>&1
```

Note: If you need more verbose output just run that command:
```bash
sudo bash veeam.harden.sh
```

## ✍ Contributions

We welcome contributions from the community! We encourage you to create [issues](https://github.com/VeeamHub/veeam-hardened-repository/issues/new/choose) for Bugs & Feature Requests and submit Pull Requests. For more detailed information, refer to our [Contributing Guide](CONTRIBUTING.md).

## 🤝🏾 License

* [MIT License](LICENSE)

## 🤔 Questions

If you have any questions or something is unclear, please don't hesitate to [create an issue](https://github.com/VeeamHub/veeam-hardened-repository/issues/new/choose) and let us know!
