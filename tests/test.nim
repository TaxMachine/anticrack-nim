import unittest
import anticrack

suite "Testing each virtual machine checks":
    test "Directory check":
        check(CheckDirectories() == false)

    test "WMI tables check":
        check(CheckWMI() == false)

    test "Registry check":
        check(CheckRegistry() == false)

    test "Check Memory caching":
        check(CheckMemoryCaching() == false)
    
    test "Check CPU cycles average":
        check(CheckCPUCyclesAverage() == false)

    test "Check bad drivers":
        check(CheckDrivers() == false)

    test "Check power state":
        check(CheckPowerState() == false)

    test "Check Screen resolution":
        check(CheckScreenResolutions() == false)

    test "Check bad device drivers":
        check(CheckDeviceDrivers() == false)

    test "Check bad Dlls":
        check(CheckDlls() == false)

    test "Check Wine":
        check(CheckWine() == false)

    test "Check bad processes":
        check(CheckVMAgentProcesses() == false)

    test "Check port connectors":
        check(CheckPortConnectors() == false)

    test "Check bad named pipes":
        check(CheckNamedPipes() == false)