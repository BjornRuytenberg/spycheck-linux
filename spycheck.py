#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
Spycheck for Linux
Copyright (C) 2020 Björn Ruytenberg <bjorn@bjornweb.nl>

This program is free software: you can redistribute it and/or modify it under the terms of the GNU
General Public License as published by the Free Software Foundation, either version 3 of the
License, or (at your option)any later version.
This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details. You should have # received a copy of the GNU General
Public License along with this program.  If not, see <http://www.gnu.org/licenses/>.

Spycheck verifies whether your system is vulnerable to the Thunderspy
attacks as detailed on https://thunderspy.io.
"""

import os
import sys
import logging
import ctypes
import platform
import argparse
from enum import Enum
from ctypes import Structure
import pathlib  # Requires Python 3.4
import time
import json

ACPI_DMAR_TABLE = "/sys/firmware/acpi/tables/DMAR"
PCI_DEV_ROOT = "/sys/bus/pci/devices"
DMI_ROOT = "/sys/devices/virtual/dmi/id"
WMI_TB_FORCE_POWER = "/sys/bus/wmi/devices/86CCFD48-205E-4A77-9C48-2021CBEDE341/force_power"
DMAR_DMA_CTRL_PLATFORM_OPT_IN_FLAG = 2

PCI_IDS = [
    # Source: https://pci-ids.ucw.cz/
    # Thunderbolt 1
    {0x1566: "DSL4410 Thunderbolt NHI [Redwood Ridge 2C 2013]"},
    {0x1568: "DSL4510 Thunderbolt NHI [Redwood Ridge 4C 2013]"},
    # Thunderbolt 2
    {0x156a: "DSL5320 Thunderbolt 2 NHI [Falcon Ridge 2C 2013]"},
    {0x156c: "DSL5520 Thunderbolt 2 NHI [Falcon Ridge 4C 2013]"},
    # Thunderbolt 3
    {0x1575: "DSL6340 Thunderbolt 3 NHI [Alpine Ridge 2C 2015]"},
    {0x1577: "DSL6540 Thunderbolt 3 NHI [Alpine Ridge 4C 2015]"},
    {0x15bf: "JHL6240 Thunderbolt 3 NHI (Low Power) [Alpine Ridge LP 2016]"},
    {0x15d2: "JHL6540 Thunderbolt 3 NHI (C step) [Alpine Ridge 4C 2016]"},
    {0x15d9: "JHL6340 Thunderbolt 3 NHI (C step) [Alpine Ridge 2C 2016]"},
    {0x15e8: "JHL7540 Thunderbolt 3 NHI [Titan Ridge 2C 2018]"},
    {0x15eb: "JHL7540 Thunderbolt 3 NHI [Titan Ridge 4C 2018]"},
    {0x8a0d: "Ice Lake Thunderbolt 3 NHI #1"},
    {0x8a17: "Ice Lake Thunderbolt 3 NHI #0"}
]


class ReportGen:
    """
    Generates reports in plaintext and a list of parameters.
    """
    # Public members
    report_output = ""
    sys_info = ""
    raw_output = []

    # Public methods
    def __init__(self, OtherPortsReportOnly):
        try:
            env_info = EnvInfo(OtherPortsReportOnly)
            self.raw_output = {
                "VulnerableState": env_info.vulnerable.value,
                "KdmaProtectionState": env_info.kdma_prot_state.value,
                "OsVersion": env_info.KernelVersion,
                "SysInfo":
                    {"SysVendor": env_info.sys_vendor,
                     "ProductName": env_info.product_name},
                "Controllers": self._controllers_to_list(env_info.controllers)
                }

            # Generate summary
            prefix = "System is" if os.geteuid() == 0 else ""
            self.report_output = "Summary:{0} {1} {2}{0}{0}".format(
                os.linesep, prefix, env_info.vulnerable.value)

            if OtherPortsReportOnly:
                self.report_output += "Your system does not have any Thunderbolt ports and is"\
                    " therefore not affected by Thunderspy."
            else:
                self.report_output += "Your system features a Thunderbolt {1}"\
                    " controller.{0}{0}".format(
                        os.linesep, env_info.controllers[0].tb_version)

                if env_info.is_mac:
                    self.report_output += "You are running Linux on an Apple Mac (Bootcamp), which"\
                        " disables all Thunderbolt security.{0}For recommendations on how to"\
                        " help protect your system, please refer to https://thunderspy.io/#protect"\
                        "ions-against-thunderspy".format(os.linesep)
                elif env_info.kdma_prot_state == env_info.KdmaPstate.Enabled:
                    self.report_output += "Your system supports Kernel DMA Protection, which"\
                        "partially mitigates Thunderspy.{0}{0}For recommendations on how to"\
                            " further protect your system, please refer to https://thunderspy.io/"\
                            "#kernel-dma-protection{0}Please note that the extent to which your"\
                            " system is partially vulnerable may change as research progresses."\
                            .format(os.linesep)
                elif env_info.kdma_prot_state == env_info.KdmaPstate.Disabled:
                    self.report_output += "Systems purchased before 2019: {0} - No fix is"\
                        " available. For recommendations on how to protect your system, please"\
                        " refer to https://thunderspy.io/#protections-against-thunderspy{0}Systems"\
                        " purchased in or after 2019: {0} - Your system might be eligible for"\
                        " Kernel DMA Protection. Please refer to https://thunderspy.io/#kernel-dma"\
                        "-protection for more information.".format(os.linesep)
                elif(env_info.kdma_prot_state == env_info.KdmaPstate.NoDmarTable
                     or env_info.kdma_prot_state ==
                     env_info.KdmaPstate.UnsupKernelAndNoDmarPresent):
                    self.report_output += "No fix is available. For recommendations on how to"\
                        " protect your system, please refer to https://thunderspy.io/#protections-"\
                        "against-thunderspy"
                elif env_info.kdma_prot_state == env_info.KdmaPstate.UnsupKernelButDmarPresent:
                    self.report_output += "Your system might be eligible for Kernel DMA"\
                        " Protection. Please upgrade to Linux kernel 5.0 or later."
                elif env_info.kdma_prot_state == env_info.KdmaPstate.UnsupKernelUnknown:
                    self.report_output += "Your kernel version '{1}' is too old and does not"\
                        " expose DMAR tables.{0} Spycheck is therefore unable to verify your"\
                        " eligibility for Kernel DMA Protection.{0}Please upgrade to kernel 3.x"\
                        " or later.".format(os.linesep, env_info.KernelVersion)
                elif env_info.kdma_prot_state == env_info.KdmaPstate.UnsupKernelButEnabled:
                    self.report_output += "Your system supports Kernel DMA Protection, but your"\
                        " Linux kernel version '{0}' does not. Please upgrade to kernel 5.0 or"\
                        " later.".format(env_info.KernelVersion)
                elif env_info.kdma_prot_state == env_info.KdmaPstate.NoRootUnknown:
                    self.report_output += "Not running as root. Cannot determine Kernel DMA"\
                        " Protection state."
                else:
                    assert False, "Uncaught envInfo.KdmaProtectionState: " + \
                        str(env_info.kdma_prot_state)

            # Generate system info
            self.sys_info = "OS version:{0} Linux kernel {1}{0}" \
                "Kernel DMA Protection:{0} {2}{0}" \
                "System vendor: {0} {3}{0}" \
                "Product name: {0} {4}{0}" \
                "{0}".format(
                    os.linesep, env_info.KernelVersion, env_info.kdma_prot_state.value,
                    env_info.sys_vendor, env_info.product_name)

            if not OtherPortsReportOnly:
                for i, controller in enumerate(env_info.controllers):
                    self.sys_info += "{0}Thunderbolt controller #{1}:" \
                                    " {0}{2}{0}" \
                                    "  Generation:{0}   Thunderbolt {3}{0}" \
                                    "  Port number:{0}   {4}{0}".format(
                                        os.linesep, i, controller.device_name,
                                        controller.tb_version,
                                        controller.num_ports)
            else:
                self.sys_info += "{0}User has indicated system does not provide any Thunderbolt"\
                    " ports. Skipping enumerating Thunderbolt controllers.".format(os.linesep)

        except NoTbControllersFoundError:
            raise
        except Exception as err:
            raise Exception("Could not generate report: ", err)

    # Private methods
    def _controllers_to_list(self, controllers):
        ctrs = []
        for i, controller in enumerate(controllers):
            ctrs.append([i, {"Controller": controller.device_name,
                             "Version": controller.tb_version,
                             "Ports": controller.num_ports}])
        return ctrs


class ControllerInfo:
    """
    Represents info about a Thunderbolt controller.
    """
    # Public members
    tb_version = 0
    device_name = "N/A"
    num_ports = 0

    # Public methods
    def __init__(self, devName):
        assert devName != "N/A", "Uncaught case: TB controller not recognized"
        self.device_name = devName

        # Determine TB version
        if "Thunderbolt NHI" in self.device_name:
            self.tb_version = 1
        elif "Thunderbolt 2 NHI" in self.device_name:
            self.tb_version = 2
        elif "Thunderbolt 3 NHI" in self.device_name:
            self.tb_version = 3
        else:
            self.tb_version = 0

        # Determine port count
        if "2C" in self.device_name:
            self.num_ports = 1
        elif "4C" in self.device_name:
            self.num_ports = 2
        else:
            self.num_ports = 0


class EnvInfo:
    """
    Collects all system environment info.
    """
    # Public members
    class KdmaPstate(Enum):
        """
        Represents Kernel DMA Protection state.
        """
        Enabled = "Enabled"
        Disabled = "Disabled"
        NoDmarTable = "No DMAR table"
        UnsupKernelButEnabled = "Unsupported kernel, but kDMAp supported and enabled by\
            system"
        UnsupKernelButDmarPresent = "Unsupported kernel, but DMAR present"
        UnsupKernelAndNoDmarPresent = "Unsupported kernel, no DMAR present"
        UnsupKernelUnknown = "Kernel too old. Cannot determine state."
        NoRootUnknown = "Root required. Cannot determine state."

    class VulnState(Enum):
        """
        Represents system vulnerability state.
        """
        Vulnerable = "Vulnerable"
        PartiallyVulnerable = "Partially Vulnerable"
        NotVulnerable = "Not Vulnerable"
        NoRootUnknown = "Root required. Cannot determine state."

    controllers = []
    KernelVersion = platform.release()
    kdma_prot_state = 0
    vulnerable = 0
    is_mac = False
    sys_vendor = ""
    product_name = ""

    # Private members
    class _acpiTableStruct(Structure):
        _pack_ = 1
        _fields_ = [  # ACPI Description Header
            ("Signature", ctypes.c_uint32),
            ("Length", ctypes.c_uint32),
            ("Revision", ctypes.c_uint8),
            ("Checksum", ctypes.c_uint8),
            ("OemId", ctypes.c_char * 6),
            ("OemTableId", ctypes.c_uint64),
            ("OemRevision", ctypes.c_uint32),
            ("CreatorId", ctypes.c_uint32),
            ("CreatorRevision", ctypes.c_uint32),
            # ACPI DMAR Header
            ("HostAddressWidth", ctypes.c_uint8),
            ("Flags", ctypes.c_uint8),
            ("Reserved", ctypes.c_uint8 * 10)]

    # Private methods
    def _is_mac(self):
        try:
            path = pathlib.Path(DMI_ROOT + "/")
            for filename in path.glob("*"):
                with open(str(filename), "r") as file_in:
                    for line in file_in:
                        if "Mac" in line:
                            return True
        except BaseException:  # pylint: disable=broad-except
            return False
        return False

    def _get_sys_vendor(self):
        vendor = ""
        try:
            with open(str(DMI_ROOT + "/sys_vendor"), "r") as file_in:
                vendor = file_in.read(-1).rstrip('\n')
        except BaseException:  # pylint: disable=broad-except
            vendor = "N/A"
        return vendor

    def _get_product_name(self):
        name = ""
        try:
            with open(str(DMI_ROOT + "/product_name"), "r") as file_in:
                name = file_in.read(-1).rstrip('\n')
        except BaseException:  # pylint: disable=broad-except
            name = "N/A"
        return name

    def _get_device_name_by_pci_id(self, pci_id):
        for device in PCI_IDS:
            if pci_id in device:
                return device[pci_id]
        return "N/A"

    def _detect_tb_controllers(self):
        tb_controllers = []
        content = ""

        path = pathlib.Path(PCI_DEV_ROOT + "/")
        for filename in path.glob("*/vendor"):
            with open(str(filename), 'r') as file:
                content = file.read()
            if content.startswith("0x8086"):
                with open(str(filename).replace("vendor", "device"), 'r') as file:
                    content = file.read()
                if(content.startswith("0x15") or content.startswith("0x8a")):
                    dev_name = self._get_device_name_by_pci_id(int(content, 16))
                    if dev_name != "N/A":
                        tb_controllers.append(ControllerInfo(dev_name))
        return tb_controllers

    def _get_tb_controllers(self):
        # Try finding controllers.
        # Some models do not expose NHI when in power saving mode (i.e. no TB devices connected).
        # If so, try again after forcing power. We do not force power until necessary, as this
        # surprisingly causes some controllers already exposing the NHI to actually disable it.

        tb_controllers = self._detect_tb_controllers()
        if len(tb_controllers) == 0:
            logging.debug("No Thunderbolt controllers found.")
            Utils.tb_set_power_state(True)
            time.sleep(3)
            tb_controllers = self._detect_tb_controllers()
            Utils.tb_set_power_state(False)
        return tb_controllers

    # Public methods
    def __init__(self, skip_enum_tb_controllers):
        kv_major = int(platform.release()[:1])
        self.is_mac = self._is_mac()
        self.sys_vendor = self._get_sys_vendor()
        self.product_name = self._get_product_name()

        try:
            file = open(ACPI_DMAR_TABLE, 'rb')
            data = file.read(-1)

            acpi_table = self._acpiTableStruct.from_buffer_copy(data)
            dmar_opt_in = (
                (acpi_table.Flags >> DMAR_DMA_CTRL_PLATFORM_OPT_IN_FLAG) & 1)

            logging.debug(
                "Signature: %s", str(acpi_table.Signature.to_bytes(4, byteorder="little",
                                                                   signed=False)))
            logging.debug("OemId: %s", str(acpi_table.OemId))
            logging.debug(
                "OemTableId: %s", str(acpi_table.OemTableId.to_bytes(8, byteorder="little",
                                                                     signed=False)))
            logging.debug(
                "CreatorId: %s", str(acpi_table.CreatorId.to_bytes(4, byteorder="little",
                                                                   signed=False)))
            logging.debug("DMAR Flags: %s", str(acpi_table.Flags))

            if dmar_opt_in == 1:
                if kv_major >= 5:
                    # Kernel supports kDMAp, and the system enables it
                    # https://github.com/torvalds/linux/commit/89a6079df791aeace2044ea93be1b397195824ec
                    self.kdma_prot_state = self.KdmaPstate.Enabled
                elif kv_major >= 3:
                    # Kernel does not support kDMAp, but system does and enables it
                    self.kdma_prot_state = self.KdmaPstate.UnsupKernelButEnabled
                elif kv_major < 3:
                    # Kernel too old and should not expose DMAR?
                    # https://github.com/torvalds/linux/commit/fa5f508f942faaf73ae5020db7a4189d5ca88d2a
                    # This case should never be triggered. If it does, we cannot trust this value.
                    self.kdma_prot_state = self.KdmaPstate.UnsupKernelUnknown

            else:
                if kv_major < 5:
                    # Kernel does not support kDMAp, but does expose DMAR through sysfs =>
                    # system does not provide IOMMU
                    self.kdma_prot_state = self.KdmaPstate.UnsupKernelButDmarPresent
                else:
                    # Kernel supports kDMAp, but system does not, or it has been disabled
                    self.kdma_prot_state = self.KdmaPstate.Disabled

            file.close()
        except IOError:
            # DMAR table does not exist

            if os.geteuid() != 0:
                # No root, so we cannot read DMAR table
                self.kdma_prot_state = self.KdmaPstate.NoRootUnknown
            else:
                if kv_major >= 5:
                    # Kernel supports kDMAp, but does not expose DMAR => system does not provide
                    # IOMMU
                    self.kdma_prot_state = self.KdmaPstate.NoDmarTable
                elif kv_major >= 3:
                    # Kernel does not expose DMAR => system does not provide IOMMU
                    self.kdma_prot_state = self.KdmaPstate.UnsupKernelAndNoDmarPresent
                elif kv_major < 3:
                    # Kernel too old and therefore does not expose DMAR => cannot tell if
                    # system provides IOMMU
                    self.kdma_prot_state = self.KdmaPstate.UnsupKernelUnknown

        except Exception as err:  # pylint: disable=broad-except
            raise Exception("Cannot parse ACPI table: ", err)

        if not skip_enum_tb_controllers:
            try:
                self.controllers = self._get_tb_controllers()
            except Exception as err:  # pylint: disable=broad-except
                raise Exception(
                    "Cannot enumerate Thunderbolt controllers: ", err)

            if len(self.controllers) == 0:
                raise NoTbControllersFoundError

        # Set vulnerable state
        if skip_enum_tb_controllers:
            self.vulnerable = self.VulnState.NotVulnerable
        else:
            if self.kdma_prot_state == self.KdmaPstate.Enabled:
                self.vulnerable = self.VulnState.PartiallyVulnerable
            elif self.kdma_prot_state == self.KdmaPstate.NoRootUnknown:
                self.vulnerable = self.VulnState.NoRootUnknown
            else:
                self.vulnerable = self.VulnState.Vulnerable


class Utils:
    """
    Various utility methods.
    """
    # Public methods
    @staticmethod
    def tb_set_power_state(state):
        """
        Sets Thunderbolt controller power state.
        """
        val = "1" if state else "0"
        en_dis = "enable" if val == "1" else "disable"

        if val:
            logging.debug("Attempting to %s power.", en_dis)

        try:
            # https://github.com/torvalds/linux/blob/ea81896dc98f324ff3fb9b1e74b4915a1beb3296/
            # Documentation/admin-guide/thunderbolt.rst#forcing-power
            with open(WMI_TB_FORCE_POWER, 'w') as file:
                file.write(val)
                logging.debug("Succesfully %sd power.", en_dis)
        except Exception as err:  # pylint: disable=broad-except
            logging.debug("Failed to %s power: %s", en_dis, err)

    @staticmethod
    def export_data_to_json_file(data, out):
        """
        Export report data to JSON-formatted file.
        """
        with open(out, 'w', encoding='utf-8') as file:
            json.dump(data, file, ensure_ascii=False, indent=4)
            file.write("\n")


class NoTbControllersFoundError(Exception):
    pass


def get_input_as_bool(question, assume_yes):
    """
    Print question, convert user input to bool, and return the latter.
    """
    # If disabling interactive mode
    if assume_yes:
        inp = "y"
        print("{0} [y/n] y".format(question))
    else:
        inp = "?"

    while inp not in ("y", "n"):
        inp = input("{0} [y/n] ".format(question))

    if inp == "y":
        return True
    return False


def main():
    """
    Main function.
    """
    parser = argparse.ArgumentParser(
        description="Spycheck for Linux", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--version", action="version",
                        version="Spycheck for Linux 1.0{0}(c) 2020 Björn Ruytenberg{0}\
                            https://thunderspy.io{0}{0}Licensed under GNU GPLv3 or later \
                                <http://gnu.org/licenses/gpl.html>.".format(os.linesep))
    parser.add_argument("-v", "--verbose", dest="verbose",
                        action="store_true", help="enable verbose output")
    parser.add_argument("-y", "--yes", dest="assumeYes",
                        action="store_true", help="disable interactive mode; assume user confirms \
                            presence of Thunderbolt ports")
    parser.add_argument("-o", "--output", dest="output",
                        action="store", help="export report to JSON-formatted file")
    args = parser.parse_args()
    logging.basicConfig(format='%(name)s: %(levelname)s: %(message)s',
                        level=logging.DEBUG if args.verbose else logging.INFO)

    report = None
    has_tb_ports = False

    if os.geteuid() != 0:
        logging.warning("No root privileges. Spycheck may not be able to detect any Thunderbolt"
                        " controllers and/or generate a complete report.")
        print(os.linesep)

    print("Welcome to Spycheck. This tool will verify whether your system is vulnerable to the "\
          "Thunderspy attacks.{0}{0}Please identify the ports on your system.".format(os.linesep))

    if get_input_as_bool("Does your system provide any USB-C or Mini-DP ports?", args.assumeYes):
        if get_input_as_bool("Is there a lightning symbol printed alongside any of these ports?",
                             args.assumeYes):
            has_tb_ports = True
            print("Enumerating, please wait...{0}".format(os.linesep))
        else:
            has_tb_ports = False
    else:
        has_tb_ports = False

    inp = True
    while inp:
        try:
            report = ReportGen(not has_tb_ports)
            print(
                "{0}{1}{0}{0}{2}".format(os.linesep, report.report_output, report.sys_info))

            if args.output is not None:
                Utils.export_data_to_json_file(report.raw_output, args.output)

            inp = False
        except NoTbControllersFoundError:
            print("{0}No Thunderbolt controllers found.{0}The system's Thunderbolt controller may"
                  " have entered power saving mode."
                  "{0}To resume operation, please connect a Thunderbolt device to one of the ports"
                  " and try again.".format(os.linesep))
            if os.geteuid() != 0:
                print(os.linesep)
                logging.warning("No root. Cannot set Thunderbolt controller power state.")
            else:
                print("{0}{0}If you keep seeing this message, your system might not provide"
                      " Thunderbolt ports.".format(os.linesep))
            print("{0}Please verify a lightning symbol is printed alongside these ports."
                  "{0}{0}If you have no Thunderbolt devices to connect, Spycheck cannot verify"
                  " whether your system is vulnerable. "
                  "{0}Please refer to https://thunderbolt.io for instructions on how to check"
                  " manually instead.{0}".format(os.linesep))
            if args.assumeYes:
                print("No controllers found. Interactive mode disabled, so aborting.")
                break

            inp = get_input_as_bool("Try again?", args.assumeYes)
        except Exception as err:  # pylint: disable=broad-except
            print("Error: ", err)
            inp = False


if __name__ == '__main__':
    if not(sys.platform == "linux" or sys.platform == "linux2"):
        print("This version of Spycheck is intended to run on Linux. If you are using Windows or"
              " macOS, please refer to https://thunderspy.io. Aborting.")
    elif sys.version_info <= (3, 4):
        print("Spycheck requires Python 3.4 or higher. Aborting.")
    else:
        main()
