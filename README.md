# Spycheck for Linux
Spycheck for Linux is a Python script that verifies whether your system is vulnerable to the Thunderspy attacks as detailed on [thunderspy.io](https://thunderspy.io). If it is found to be vulnerable, Spycheck will guide you to recommendations on how to help protect your system.

Spycheck is also available for [Windows](https://thunderspy.io/#TODO-FIX-ME). Instructions on how to verify your system on macOS may be found [here](https://thunderspy.io/#TODO-FIX-ME).

## Requirements
Spycheck for Linux supports:

- Linux kernel 3.16 and later
- Python 3.4 and later
- All Thunderbolt 2 and 3 host controllers
- PCs as well as Apple Mac systems running Linux (Bootcamp)

Spycheck works independently of the `thunderbolt` kernel module, and will therefore function even if your kernel blacklists or does not provide this module.

## Usage
This tool requires [root privileges](#qa-root-req) to generate an accurate report. To verify whether your system is vulnerable to Thunderspy, simply run the script as follows:

    $ sudo python3 spycheck.py

When running Spycheck, you will be asked to identify the ports on your system. If you indicate your system provides Thunderbolt ports, the tool will attempt to detect Thunderbolt hardware and assess whether your system is vulnerable to Thunderspy.

Example output:

    Welcome to Spycheck. This tool will verify whether your system is vulnerable to the Thunderspy attacks.

    Please identify the ports on your system.
    Does your system provide any USB-C or Mini-DP ports? [y/n] y
    Is there a lightning symbol printed alongside any of these ports? [y/n] y
    Enumerating, please wait...


    Summary:
    System is Vulnerable

    Your system features a Thunderbolt 3 controller.

    No fix is available. For recommendations on how to protect your system, please refer to https://thunderspy.io/#protections-against-thunderspy

    OS version:
     Linux kernel 5.3.0-42-generic
    Kernel DMA Protection:
     No DMAR table
    System vendor: 
      HP
    Product name: 
      ZBook 15 G4


    Thunderbolt controller #0: 
    JHL6540 Thunderbolt 3 NHI (C step) [Alpine Ridge 4C 2016]
      Generation:
       Thunderbolt 3
      Port number:
       2


## Advanced usage
Spycheck optionally supports the following commands:

    usage: spycheck.py [-h] [--version] [-v] [-y] [-o OUTPUT]

    Spycheck for Linux

    optional arguments:
    -h, --help            show this help message and exit
    --version             show program's version number and exit
    -v, --verbose         enable verbose output
    -y, --yes             disable interactive mode; assume user confirms
                            presence of Thunderbolt ports
    -o OUTPUT, --output OUTPUT
                            export report to JSON-formatted file

## Questions and Answers

### <a name="qa-root-req"></a>Why does Spycheck require root privileges to generate an accurate report?
While Spycheck will work without root privileges, it may not be able to generate an accurate report. Root privileges are required to:

- Read the DMAR table from ACPI, to get Kernel DMA Protection state
- Read DMI, to determine whether the system is an Apple Mac
- Read and write WMI, to set the Thunderbolt controller power state if it's running in power saving mode

### I don't have any Thunderbolt devices. Will Spycheck still work?
On some systems, the Thunderbolt controller may enter power saving mode when no Thunderbolt devices are attached. In this case, Spycheck will attempt to enable power using the [WMI Thunderbolt driver](https://github.com/torvalds/linux/commit/ce6a90027c10f970f872de5db0294f9e3e969f1c#diff-249537ec6906ef50bd746f888541f4d9). If your system requires disabling power saving mode, and you don't have any Thunderbolt devices to connect, please ensure to run a kernel that ships the former driver (4.15 or later).

### Can I run Spycheck as part of my scripts?
Yes. Simply pass `-y` to disable interactive mode. To export the report to a JSON-formatted file as well, use `-y -o FILE`.

### I would prefer checking my system manually. How can I do this?
Please refer to [thunderspy.io](https://thunderspy.io) for instructions on how to manually check whether your system is vulnerable.

## License
See the [LICENSE](LICENSE) file.