#include "apphandler.hpp"

#include "app/watchdog.hpp"
#include "sys_info_param.hpp"
#include "transporthandler.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <ipmid/api.h>
#include <limits.h>
#include <linux/i2c-dev.h>
#include <linux/i2c.h>
#include <mapper.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <systemd/sd-bus.h>
#include <unistd.h>

#include <algorithm>
#include <app/channel.hpp>
#include <app/watchdog.hpp>
#include <apphandler.hpp>
#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <ipmid/api.hpp>
#include <ipmid/types.hpp>
#include <ipmid/utils.hpp>
#include <memory>
#include <nlohmann/json.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/message/types.hpp>
#include <string>
#include <sys_info_param.hpp>
#include <transporthandler.hpp>
#include <tuple>
#include <vector>
#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/Control/Power/ACPIPowerState/server.hpp>
#include <xyz/openbmc_project/Software/Activation/server.hpp>
#include <xyz/openbmc_project/Software/Version/server.hpp>
#include <xyz/openbmc_project/State/BMC/server.hpp>

extern sd_bus* bus;

constexpr auto bmc_state_interface = "xyz.openbmc_project.State.BMC";
constexpr auto bmc_state_property = "CurrentBMCState";
// phosphor-setting-manager is the unique service that holds this interface
constexpr auto bmc_guid_interface = "xyz.openbmc_project.Common.UUID";
constexpr auto bmc_guid_property = "UUID";
constexpr auto bmc_guid_len = 16;

static constexpr uint8_t maxIPMIWriteReadSize = 144;

static constexpr auto redundancyIntf =
    "xyz.openbmc_project.Software.RedundancyPriority";
static constexpr auto versionIntf = "xyz.openbmc_project.Software.Version";
static constexpr auto activationIntf =
    "xyz.openbmc_project.Software.Activation";
static constexpr auto softwareRoot = "/xyz/openbmc_project/software";

void register_netfn_app_functions() __attribute__((constructor));

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
using Version = sdbusplus::xyz::openbmc_project::Software::server::Version;
using Activation =
    sdbusplus::xyz::openbmc_project::Software::server::Activation;
using BMC = sdbusplus::xyz::openbmc_project::State::server::BMC;
namespace fs = std::filesystem;
namespace variant_ns = sdbusplus::message::variant_ns;

// Offset in get device id command.
typedef struct
{
    uint8_t id;
    uint8_t revision;
    uint8_t fw[2];
    uint8_t ipmi_ver;
    uint8_t addn_dev_support;
    uint8_t manuf_id[3];
    uint8_t prod_id[2];
    uint8_t aux[4];
} __attribute__((packed)) ipmi_device_id_t;

typedef struct
{
    uint8_t busId;
    uint8_t slaveAddr;
    uint8_t readCount;
} __attribute__((packed)) ipmiI2cRwReq;

typedef struct
{
    uint8_t busId;
    uint8_t slaveAddr;
    std::vector<uint8_t> data;
} ipmiMasterRwWhitelist;

static std::vector<ipmiMasterRwWhitelist>& getWhiteList()
{
    static std::vector<ipmiMasterRwWhitelist> rwWhiteList;
    return rwWhiteList;
}

static constexpr const char* whiteListFilename =
    "/usr/share/ipmi-providers/master_write_read_white_list.json";

static constexpr const char* filtersStr = "filters";
static constexpr const char* busIdStr = "busId";
static constexpr const char* slaveAddrStr = "slaveAddr";
static constexpr const char* cmdStr = "command";

/**
 * @brief Returns the Version info from primary s/w object
 *
 * Get the Version info from the active s/w object which is having high
 * "Priority" value(a smaller number is a higher priority) and "Purpose"
 * is "BMC" from the list of all s/w objects those are implementing
 * RedundancyPriority interface from the given softwareRoot path.
 *
 * @return On success returns the Version info from primary s/w object.
 *
 */
std::string getActiveSoftwareVersionInfo()
{
    auto busp = getSdBus();

    std::string revision{};
    ipmi::ObjectTree objectTree;
    try
    {
        objectTree =
            ipmi::getAllDbusObjects(*busp, softwareRoot, redundancyIntf);
    }
    catch (sdbusplus::exception::SdBusError& e)
    {
        log<level::ERR>("Failed to fetch redundancy object from dbus",
                        entry("INTERFACE=%s", redundancyIntf),
                        entry("ERRMSG=%s", e.what()));
        elog<InternalFailure>();
    }

    auto objectFound = false;
    for (auto& softObject : objectTree)
    {
        auto service =
            ipmi::getService(*busp, redundancyIntf, softObject.first);
        auto objValueTree =
            ipmi::getManagedObjects(*busp, service, softwareRoot);

        auto minPriority = 0xFF;
        for (const auto& objIter : objValueTree)
        {
            try
            {
                auto& intfMap = objIter.second;
                auto& redundancyPriorityProps = intfMap.at(redundancyIntf);
                auto& versionProps = intfMap.at(versionIntf);
                auto& activationProps = intfMap.at(activationIntf);
                auto priority = variant_ns::get<uint8_t>(
                    redundancyPriorityProps.at("Priority"));
                auto purpose =
                    variant_ns::get<std::string>(versionProps.at("Purpose"));
                auto activation = variant_ns::get<std::string>(
                    activationProps.at("Activation"));
                auto version =
                    variant_ns::get<std::string>(versionProps.at("Version"));
                if ((Version::convertVersionPurposeFromString(purpose) ==
                     Version::VersionPurpose::BMC) &&
                    (Activation::convertActivationsFromString(activation) ==
                     Activation::Activations::Active))
                {
                    if (priority < minPriority)
                    {
                        minPriority = priority;
                        objectFound = true;
                        revision = std::move(version);
                    }
                }
            }
            catch (const std::exception& e)
            {
                log<level::ERR>(e.what());
            }
        }
    }

    if (!objectFound)
    {
        log<level::ERR>("Could not found an BMC software Object");
        elog<InternalFailure>();
    }

    return revision;
}

bool getCurrentBmcState()
{
    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};

    // Get the Inventory object implementing the BMC interface
    ipmi::DbusObjectInfo bmcObject =
        ipmi::getDbusObject(bus, bmc_state_interface);
    auto variant =
        ipmi::getDbusProperty(bus, bmcObject.second, bmcObject.first,
                              bmc_state_interface, bmc_state_property);

    return variant_ns::holds_alternative<std::string>(variant) &&
           BMC::convertBMCStateFromString(
               variant_ns::get<std::string>(variant)) == BMC::BMCState::Ready;
}

namespace acpi_state
{
using namespace sdbusplus::xyz::openbmc_project::Control::Power::server;

const static constexpr char* acpiObjPath =
    "/xyz/openbmc_project/control/host0/acpi_power_state";
const static constexpr char* acpiInterface =
    "xyz.openbmc_project.Control.Power.ACPIPowerState";
const static constexpr char* sysACPIProp = "SysACPIStatus";
const static constexpr char* devACPIProp = "DevACPIStatus";

enum class PowerStateType : uint8_t
{
    sysPowerState = 0x00,
    devPowerState = 0x01,
};

// Defined in 20.6 of ipmi doc
enum class PowerState : uint8_t
{
    s0G0D0 = 0x00,
    s1D1 = 0x01,
    s2D2 = 0x02,
    s3D3 = 0x03,
    s4 = 0x04,
    s5G2 = 0x05,
    s4S5 = 0x06,
    g3 = 0x07,
    sleep = 0x08,
    g1Sleep = 0x09,
    override = 0x0a,
    legacyOn = 0x20,
    legacyOff = 0x21,
    unknown = 0x2a,
    noChange = 0x7f,
};

static constexpr uint8_t stateChanged = 0x80;

struct ACPIState
{
    uint8_t sysACPIState;
    uint8_t devACPIState;
} __attribute__((packed));

std::map<ACPIPowerState::ACPI, PowerState> dbusToIPMI = {
    {ACPIPowerState::ACPI::S0_G0_D0, PowerState::s0G0D0},
    {ACPIPowerState::ACPI::S1_D1, PowerState::s1D1},
    {ACPIPowerState::ACPI::S2_D2, PowerState::s2D2},
    {ACPIPowerState::ACPI::S3_D3, PowerState::s3D3},
    {ACPIPowerState::ACPI::S4, PowerState::s4},
    {ACPIPowerState::ACPI::S5_G2, PowerState::s5G2},
    {ACPIPowerState::ACPI::S4_S5, PowerState::s4S5},
    {ACPIPowerState::ACPI::G3, PowerState::g3},
    {ACPIPowerState::ACPI::SLEEP, PowerState::sleep},
    {ACPIPowerState::ACPI::G1_SLEEP, PowerState::g1Sleep},
    {ACPIPowerState::ACPI::OVERRIDE, PowerState::override},
    {ACPIPowerState::ACPI::LEGACY_ON, PowerState::legacyOn},
    {ACPIPowerState::ACPI::LEGACY_OFF, PowerState::legacyOff},
    {ACPIPowerState::ACPI::Unknown, PowerState::unknown}};

bool isValidACPIState(acpi_state::PowerStateType type, uint8_t state)
{
    if (type == acpi_state::PowerStateType::sysPowerState)
    {
        if ((state <= static_cast<uint8_t>(acpi_state::PowerState::override)) ||
            (state == static_cast<uint8_t>(acpi_state::PowerState::legacyOn)) ||
            (state ==
             static_cast<uint8_t>(acpi_state::PowerState::legacyOff)) ||
            (state == static_cast<uint8_t>(acpi_state::PowerState::unknown)) ||
            (state == static_cast<uint8_t>(acpi_state::PowerState::noChange)))
        {
            return true;
        }
        else
        {
            return false;
        }
    }
    else if (type == acpi_state::PowerStateType::devPowerState)
    {
        if ((state <= static_cast<uint8_t>(acpi_state::PowerState::s3D3)) ||
            (state == static_cast<uint8_t>(acpi_state::PowerState::unknown)) ||
            (state == static_cast<uint8_t>(acpi_state::PowerState::noChange)))
        {
            return true;
        }
        else
        {
            return false;
        }
    }
    else
    {
        return false;
    }
    return false;
}
} // namespace acpi_state

ipmi_ret_t ipmi_app_set_acpi_power_state(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                         ipmi_request_t request,
                                         ipmi_response_t response,
                                         ipmi_data_len_t data_len,
                                         ipmi_context_t context)
{
    auto s = static_cast<uint8_t>(acpi_state::PowerState::unknown);
    ipmi_ret_t rc = IPMI_CC_OK;

    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};

    auto value = acpi_state::ACPIPowerState::ACPI::Unknown;

    auto* req = reinterpret_cast<acpi_state::ACPIState*>(request);

    if (*data_len != sizeof(acpi_state::ACPIState))
    {
        log<level::ERR>("set_acpi invalid len");
        *data_len = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    *data_len = 0;

    if (req->sysACPIState & acpi_state::stateChanged)
    {
        // set system power state
        s = req->sysACPIState & ~acpi_state::stateChanged;

        if (!acpi_state::isValidACPIState(
                acpi_state::PowerStateType::sysPowerState, s))
        {
            log<level::ERR>("set_acpi_power sys invalid input",
                            entry("S=%x", s));
            return IPMI_CC_PARM_OUT_OF_RANGE;
        }

        // valid input
        if (s == static_cast<uint8_t>(acpi_state::PowerState::noChange))
        {
            log<level::DEBUG>("No change for system power state");
        }
        else
        {
            auto found = std::find_if(
                acpi_state::dbusToIPMI.begin(), acpi_state::dbusToIPMI.end(),
                [&s](const auto& iter) {
                    return (static_cast<uint8_t>(iter.second) == s);
                });

            value = found->first;

            try
            {
                auto acpiObject =
                    ipmi::getDbusObject(bus, acpi_state::acpiInterface);
                ipmi::setDbusProperty(bus, acpiObject.second, acpiObject.first,
                                      acpi_state::acpiInterface,
                                      acpi_state::sysACPIProp,
                                      convertForMessage(value));
            }
            catch (const InternalFailure& e)
            {
                log<level::ERR>("Failed in set ACPI system property",
                                entry("EXCEPTION=%s", e.what()));
                return IPMI_CC_UNSPECIFIED_ERROR;
            }
        }
    }
    else
    {
        log<level::DEBUG>("Do not change system power state");
    }

    if (req->devACPIState & acpi_state::stateChanged)
    {
        // set device power state
        s = req->devACPIState & ~acpi_state::stateChanged;
        if (!acpi_state::isValidACPIState(
                acpi_state::PowerStateType::devPowerState, s))
        {
            log<level::ERR>("set_acpi_power dev invalid input",
                            entry("S=%x", s));
            return IPMI_CC_PARM_OUT_OF_RANGE;
        }

        // valid input
        if (s == static_cast<uint8_t>(acpi_state::PowerState::noChange))
        {
            log<level::DEBUG>("No change for device power state");
        }
        else
        {
            auto found = std::find_if(
                acpi_state::dbusToIPMI.begin(), acpi_state::dbusToIPMI.end(),
                [&s](const auto& iter) {
                    return (static_cast<uint8_t>(iter.second) == s);
                });

            value = found->first;

            try
            {
                auto acpiObject =
                    ipmi::getDbusObject(bus, acpi_state::acpiInterface);
                ipmi::setDbusProperty(bus, acpiObject.second, acpiObject.first,
                                      acpi_state::acpiInterface,
                                      acpi_state::devACPIProp,
                                      convertForMessage(value));
            }
            catch (const InternalFailure& e)
            {
                log<level::ERR>("Failed in set ACPI device property",
                                entry("EXCEPTION=%s", e.what()));
                return IPMI_CC_UNSPECIFIED_ERROR;
            }
        }
    }
    else
    {
        log<level::DEBUG>("Do not change device power state");
    }

    return rc;
}

ipmi_ret_t ipmi_app_get_acpi_power_state(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                         ipmi_request_t request,
                                         ipmi_response_t response,
                                         ipmi_data_len_t data_len,
                                         ipmi_context_t context)
{
    ipmi_ret_t rc = IPMI_CC_OK;

    auto* res = reinterpret_cast<acpi_state::ACPIState*>(response);

    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};

    *data_len = 0;

    try
    {
        auto acpiObject = ipmi::getDbusObject(bus, acpi_state::acpiInterface);

        auto sysACPIVal = ipmi::getDbusProperty(
            bus, acpiObject.second, acpiObject.first, acpi_state::acpiInterface,
            acpi_state::sysACPIProp);
        auto sysACPI = acpi_state::ACPIPowerState::convertACPIFromString(
            variant_ns::get<std::string>(sysACPIVal));
        res->sysACPIState =
            static_cast<uint8_t>(acpi_state::dbusToIPMI.at(sysACPI));

        auto devACPIVal = ipmi::getDbusProperty(
            bus, acpiObject.second, acpiObject.first, acpi_state::acpiInterface,
            acpi_state::devACPIProp);
        auto devACPI = acpi_state::ACPIPowerState::convertACPIFromString(
            variant_ns::get<std::string>(devACPIVal));
        res->devACPIState =
            static_cast<uint8_t>(acpi_state::dbusToIPMI.at(devACPI));

        *data_len = sizeof(acpi_state::ACPIState);
    }
    catch (const InternalFailure& e)
    {
        log<level::ERR>("Failed in get ACPI property");
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    return rc;
}

typedef struct
{
    char major;
    char minor;
    uint16_t d[2];
} Revision;

/* Currently supports the vx.x-x-[-x] and v1.x.x-x-[-x] format. It will     */
/* return -1 if not in those formats, this routine knows how to parse       */
/* version = v0.6-19-gf363f61-dirty                                         */
/*            ^ ^ ^^          ^                                             */
/*            | |  |----------|-- additional details                        */
/*            | |---------------- Minor                                     */
/*            |------------------ Major                                     */
/* and version = v1.99.10-113-g65edf7d-r3-0-g9e4f715                        */
/*                ^ ^  ^^ ^                                                 */
/*                | |  |--|---------- additional details                    */
/*                | |---------------- Minor                                 */
/*                |------------------ Major                                 */
/* Additional details : If the option group exists it will force Auxiliary  */
/* Firmware Revision Information 4th byte to 1 indicating the build was     */
/* derived with additional edits                                            */
int convertVersion(std::string s, Revision& rev)
{
    std::string token;
    uint16_t commits;

    auto location = s.find_first_of('v');
    if (location != std::string::npos)
    {
        s = s.substr(location + 1);
    }

    if (!s.empty())
    {
        location = s.find_first_of(".");
        if (location != std::string::npos)
        {
            rev.major =
                static_cast<char>(std::stoi(s.substr(0, location), 0, 16));
            token = s.substr(location + 1);
        }

        if (!token.empty())
        {
            location = token.find_first_of(".-");
            if (location != std::string::npos)
            {
                rev.minor = static_cast<char>(
                    std::stoi(token.substr(0, location), 0, 16));
                token = token.substr(location + 1);
            }
        }

        // Capture the number of commits on top of the minor tag.
        // I'm using BE format like the ipmi spec asked for
        location = token.find_first_of(".-");
        if (!token.empty())
        {
            commits = std::stoi(token.substr(0, location), 0, 16);
            rev.d[0] = (commits >> 8) | (commits << 8);

            // commit number we skip
            location = token.find_first_of(".-");
            if (location != std::string::npos)
            {
                token = token.substr(location + 1);
            }
        }
        else
        {
            rev.d[0] = 0;
        }

        if (location != std::string::npos)
        {
            token = token.substr(location + 1);
        }

        // Any value of the optional parameter forces it to 1
        location = token.find_first_of(".-");
        if (location != std::string::npos)
        {
            token = token.substr(location + 1);
        }
        commits = (!token.empty()) ? 1 : 0;

        // We do this operation to get this displayed in least significant bytes
        // of ipmitool device id command.
        rev.d[1] = (commits >> 8) | (commits << 8);
    }

    return 0;
}

auto ipmiAppGetDeviceId() -> ipmi::RspType<uint8_t, // Device ID
                                           uint8_t, // Device Revision
                                           uint8_t, // Firmware Revision Major
                                           uint8_t, // Firmware Revision minor
                                           uint8_t, // IPMI version
                                           uint8_t, // Additional device support
                                           uint24_t, // MFG ID
                                           uint16_t, // Product ID
                                           uint32_t  // AUX info
                                           >
{
    int r = -1;
    Revision rev = {0};
    static struct
    {
        uint8_t id;
        uint8_t revision;
        uint8_t fw[2];
        uint8_t ipmiVer;
        uint8_t addnDevSupport;
        uint24_t manufId;
        uint16_t prodId;
        uint32_t aux;
    } devId;
    static bool dev_id_initialized = false;
    const char* filename = "/usr/share/ipmi-providers/dev_id.json";
    constexpr auto ipmiDevIdStateShift = 7;
    constexpr auto ipmiDevIdFw1Mask = ~(1 << ipmiDevIdStateShift);

    if (!dev_id_initialized)
    {
        try
        {
            auto version = getActiveSoftwareVersionInfo();
            r = convertVersion(version, rev);
        }
        catch (const std::exception& e)
        {
            log<level::ERR>(e.what());
        }

        if (r >= 0)
        {
            // bit7 identifies if the device is available
            // 0=normal operation
            // 1=device firmware, SDR update,
            // or self-initialization in progress.
            // The availability may change in run time, so mask here
            // and initialize later.
            devId.fw[0] = rev.major & ipmiDevIdFw1Mask;

            rev.minor = (rev.minor > 99 ? 99 : rev.minor);
            devId.fw[1] = rev.minor % 10 + (rev.minor / 10) * 16;
            std::memcpy(&devId.aux, rev.d, 4);
        }

        // IPMI Spec version 2.0
        devId.ipmiVer = 2;

        std::ifstream devIdFile(filename);
        if (devIdFile.is_open())
        {
            auto data = nlohmann::json::parse(devIdFile, nullptr, false);
            if (!data.is_discarded())
            {
                devId.id = data.value("id", 0);
                devId.revision = data.value("revision", 0);
                devId.addnDevSupport = data.value("addn_dev_support", 0);
                devId.manufId = data.value("manuf_id", 0);
                devId.prodId = data.value("prod_id", 0);
                devId.aux = data.value("aux", 0);

                // Don't read the file every time if successful
                dev_id_initialized = true;
            }
            else
            {
                log<level::ERR>("Device ID JSON parser failure");
                return ipmi::responseUnspecifiedError();
            }
        }
        else
        {
            log<level::ERR>("Device ID file not found");
            return ipmi::responseUnspecifiedError();
        }
    }

    // Set availability to the actual current BMC state
    devId.fw[0] &= ipmiDevIdFw1Mask;
    if (!getCurrentBmcState())
    {
        devId.fw[0] |= (1 << ipmiDevIdStateShift);
    }

    return ipmi::responseSuccess(
        devId.id, devId.revision, devId.fw[0], devId.fw[1], devId.ipmiVer,
        devId.addnDevSupport, devId.manufId, devId.prodId, devId.aux);
}

auto ipmiAppGetSelfTestResults() -> ipmi::RspType<uint8_t, uint8_t>
{
    // Byte 2:
    //  55h - No error.
    //  56h - Self Test function not implemented in this controller.
    //  57h - Corrupted or inaccesssible data or devices.
    //  58h - Fatal hardware error.
    //  FFh - reserved.
    //  all other: Device-specific 'internal failure'.
    //  Byte 3:
    //      For byte 2 = 55h, 56h, FFh:     00h
    //      For byte 2 = 58h, all other:    Device-specific
    //      For byte 2 = 57h:   self-test error bitfield.
    //      Note: returning 57h does not imply that all test were run.
    //      [7] 1b = Cannot access SEL device.
    //      [6] 1b = Cannot access SDR Repository.
    //      [5] 1b = Cannot access BMC FRU device.
    //      [4] 1b = IPMB signal lines do not respond.
    //      [3] 1b = SDR Repository empty.
    //      [2] 1b = Internal Use Area of BMC FRU corrupted.
    //      [1] 1b = controller update 'boot block' firmware corrupted.
    //      [0] 1b = controller operational firmware corrupted.
    constexpr uint8_t notImplemented = 0x56;
    constexpr uint8_t zero = 0;
    return ipmi::responseSuccess(notImplemented, zero);
}

ipmi_ret_t ipmi_app_get_device_guid(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                    ipmi_request_t request,
                                    ipmi_response_t response,
                                    ipmi_data_len_t data_len,
                                    ipmi_context_t context)
{
    const char* objname =
        "/xyz/openbmc_project/inventory/system/chassis/motherboard/bmc";
    const char* iface = "org.freedesktop.DBus.Properties";
    const char* uuid_iface = "xyz.openbmc_project.Common.UUID";
    sd_bus_message* reply = NULL;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    int r = 0;
    char* uuid = NULL;
    char* busname = NULL;

    // UUID is in RFC4122 format. Ex: 61a39523-78f2-11e5-9862-e6402cfc3223
    // Per IPMI Spec 2.0 need to convert to 16 hex bytes and reverse the byte
    // order
    // Ex: 0x2332fc2c40e66298e511f2782395a361

    const int resp_size = 16;     // Response is 16 hex bytes per IPMI Spec
    uint8_t resp_uuid[resp_size]; // Array to hold the formatted response
    // Point resp end of array to save in reverse order
    int resp_loc = resp_size - 1;
    int i = 0;
    char* tokptr = NULL;
    char* id_octet = NULL;
    size_t total_uuid_size = 0;
    // 1 byte of resp is built from 2 chars of uuid.
    constexpr size_t max_uuid_size = 2 * resp_size;

    // Status code.
    ipmi_ret_t rc = IPMI_CC_OK;
    *data_len = 0;

    // Call Get properties method with the interface and property name
    r = mapper_get_service(bus, objname, &busname);
    if (r < 0)
    {
        log<level::ERR>("Failed to get bus name", entry("BUS=%s", objname),
                        entry("ERRNO=0x%X", -r));
        goto finish;
    }

    r = sd_bus_call_method(bus, busname, objname, iface, "Get", &error, &reply,
                           "ss", uuid_iface, "UUID");
    if (r < 0)
    {
        log<level::ERR>("Failed to call Get Method", entry("ERRNO=0x%X", -r));
        rc = IPMI_CC_UNSPECIFIED_ERROR;
        goto finish;
    }

    r = sd_bus_message_read(reply, "v", "s", &uuid);
    if (r < 0 || uuid == NULL)
    {
        log<level::ERR>("Failed to get a response", entry("ERRNO=0x%X", -r));
        rc = IPMI_CC_RESPONSE_ERROR;
        goto finish;
    }

    // Traverse the UUID
    // Get the UUID octects separated by dash
    id_octet = strtok_r(uuid, "-", &tokptr);

    if (id_octet == NULL)
    {
        // Error
        log<level::ERR>("Unexpected UUID format", entry("UUID=%s", uuid));
        rc = IPMI_CC_RESPONSE_ERROR;
        goto finish;
    }

    while (id_octet != NULL)
    {
        // Calculate the octet string size since it varies
        // Divide it by 2 for the array size since 1 byte is built from 2 chars
        int tmp_size = strlen(id_octet) / 2;

        // Check if total UUID size has been exceeded
        if ((total_uuid_size += strlen(id_octet)) > max_uuid_size)
        {
            // Error - UUID too long to store
            log<level::ERR>("UUID too long", entry("UUID=%s", uuid));
            rc = IPMI_CC_RESPONSE_ERROR;
            goto finish;
        }

        for (i = 0; i < tmp_size; i++)
        {
            // Holder of the 2 chars that will become a byte
            char tmp_array[3] = {0};
            strncpy(tmp_array, id_octet, 2); // 2 chars at a time

            int resp_byte = strtoul(tmp_array, NULL, 16); // Convert to hex byte
            // Copy end to first
            std::memcpy((void*)&resp_uuid[resp_loc], &resp_byte, 1);
            resp_loc--;
            id_octet += 2; // Finished with the 2 chars, advance
        }
        id_octet = strtok_r(NULL, "-", &tokptr); // Get next octet
    }

    // Data length
    *data_len = resp_size;

    // Pack the actual response
    std::memcpy(response, &resp_uuid, *data_len);

finish:
    sd_bus_error_free(&error);
    reply = sd_bus_message_unref(reply);
    free(busname);

    return rc;
}

auto ipmiAppGetBtCapabilities()
    -> ipmi::RspType<uint8_t, uint8_t, uint8_t, uint8_t, uint8_t>
{
    // Per IPMI 2.0 spec, the input and output buffer size must be the max
    // buffer size minus one byte to allocate space for the length byte.
    constexpr uint8_t nrOutstanding = 0x01;
    constexpr uint8_t inputBufferSize = MAX_IPMI_BUFFER - 1;
    constexpr uint8_t outputBufferSize = MAX_IPMI_BUFFER - 1;
    constexpr uint8_t transactionTime = 0x0A;
    constexpr uint8_t nrRetries = 0x01;

    return ipmi::responseSuccess(nrOutstanding, inputBufferSize,
                                 outputBufferSize, transactionTime, nrRetries);
}

ipmi_ret_t ipmi_app_get_sys_guid(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                 ipmi_request_t request,
                                 ipmi_response_t response,
                                 ipmi_data_len_t data_len,
                                 ipmi_context_t context)

{
    ipmi_ret_t rc = IPMI_CC_OK;
    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};

    try
    {
        // Get the Inventory object implementing BMC interface
        ipmi::DbusObjectInfo bmcObject =
            ipmi::getDbusObject(bus, bmc_guid_interface);
        // Read UUID property value from bmcObject
        // UUID is in RFC4122 format Ex: 61a39523-78f2-11e5-9862-e6402cfc3223
        auto variant =
            ipmi::getDbusProperty(bus, bmcObject.second, bmcObject.first,
                                  bmc_guid_interface, bmc_guid_property);
        std::string guidProp = variant_ns::get<std::string>(variant);

        // Erase "-" characters from the property value
        guidProp.erase(std::remove(guidProp.begin(), guidProp.end(), '-'),
                       guidProp.end());

        auto guidPropLen = guidProp.length();
        // Validate UUID data
        // Divide by 2 as 1 byte is built from 2 chars
        if ((guidPropLen <= 0) || ((guidPropLen / 2) != bmc_guid_len))

        {
            log<level::ERR>("Invalid UUID property value",
                            entry("UUID_LENGTH=%d", guidPropLen));
            return IPMI_CC_RESPONSE_ERROR;
        }

        // Convert data in RFC4122(MSB) format to LSB format
        // Get 2 characters at a time as 1 byte is built from 2 chars and
        // convert to hex byte
        // TODO: Data printed for GUID command is not as per the
        // GUID format defined in IPMI specification 2.0 section 20.8
        // Ticket raised: https://sourceforge.net/p/ipmitool/bugs/501/
        uint8_t respGuid[bmc_guid_len];
        for (size_t i = 0, respLoc = (bmc_guid_len - 1);
             i < guidPropLen && respLoc >= 0; i += 2, respLoc--)
        {
            auto value = static_cast<uint8_t>(
                std::stoi(guidProp.substr(i, 2).c_str(), NULL, 16));
            respGuid[respLoc] = value;
        }

        *data_len = bmc_guid_len;
        std::memcpy(response, &respGuid, bmc_guid_len);
    }
    catch (const InternalFailure& e)
    {
        log<level::ERR>("Failed in reading BMC UUID property",
                        entry("PROPERTY_INTERFACE=%s", bmc_guid_interface),
                        entry("PROPERTY=%s", bmc_guid_property));
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    return rc;
}

static std::unique_ptr<SysInfoParamStore> sysInfoParamStore;



struct IpmiSysInfoResp
{
    uint8_t paramRevision;
    union
    {
        struct
        {
            uint8_t setSelector;
            union
            {
                struct
                {
                    uint8_t encoding;
                    uint8_t stringLen;
                    uint8_t stringData0[14];
                } __attribute__((packed));
                uint8_t stringDataN[16];
            };
        } __attribute__((packed));
        uint8_t byteData;
    };
} __attribute__((packed));

/**
 * Split a string into (up to) 16-byte chunks as expected in response for get
 * system info parameter.
 *
 * @param[in] fullString: Input string to be split
 * @param[in] chunkIndex: Index of the chunk to be written out
 * @param[in,out] chunk: Output data buffer; must have 14 byte capacity if
 *          chunk_index = 0 and 16-byte capacity otherwise
 * @return the number of bytes written into the output buffer, or -EINVAL for
 * invalid arguments.
 */
static int splitStringParam(
    const IpmiSysInfo& fullString, int chunkIndex,
    uint8_t* chunk)
{

    if (chunkIndex > maxChunk || chunk == nullptr)
    {
        return -EINVAL;
    }
    try
    {
        if (chunkIndex == 0)
        {
            // Output must have 14 byte capacity.
            std::copy_n(fullString.stringDataN, smallChunkSize, chunk);
            return smallChunkSize;
        }
        else
        {
            // Output must have 16 byte capacity.
            std::copy_n(fullString.stringDataN + (chunkIndex * chunkSize) - 2,
                        chunkSize,  chunk);
            return chunkSize;
        }
    }
    catch (const std::out_of_range& e)
    {
        // The position was beyond the end.
        return -EINVAL;
    }
}

/**
 * Packs the Get Sys Info Request Item into the response.
 *
 * @param[in] param - the parameter.
 * @param[in] setSelector - the selector
 * @param[in,out] resp - the System info response.
 * @return The number of bytes packed or failure from splitStringParam().
 */
static int
    packGetSysInfoResp(const IpmiSysInfo& param,
                       uint8_t setSelector, IpmiSysInfoResp* resp)
{
    uint8_t* dataBuffer = resp->stringDataN;
    resp->setSelector = setSelector;
    if (resp->setSelector == 0) // First chunk has only 14 bytes.
    {
        resp->encoding = 0; //TODO
        resp->stringLen = smallChunkSize;
        dataBuffer = resp->stringData0;
    }
    return splitStringParam(param, resp->setSelector, dataBuffer);
}

static constexpr uint8_t setComplete = 0x0;
static constexpr uint8_t setInProgress = 0x1;
static constexpr uint8_t commitWrite = 0x2;
uint8_t transferStatus = setComplete;

static constexpr uint8_t encodingASCII = 0x0; // ASCII+Latin1
static constexpr uint8_t encodingUTF8 = 0x1;
static constexpr uint8_t encodingUNICODE = 0x2;

// each parameter could have multiple bytes for content storage
// every IPMI transfer can only upload 16bytes.

static constexpr uint8_t bytesPerChunk = 16;
static constexpr uint8_t chunksLimit = (maxBytesPerParameter / bytesPerChunk);

static IpmiSysInfo sysInfoReadSystemName()
{
    IpmiSysInfo sysname;
    // Use the BMC hostname as the "System Name."
    char hostname[HOST_NAME_MAX + 1] = {};
    if (gethostname(hostname, HOST_NAME_MAX) != 0)
    {
        perror("System info parameter: system name");
    }
    std::string host = hostname;
    sysname.encoding = encodingASCII;
    sysname.stringLen = host.size();
    std::copy_n(host.begin(), host.size(), sysname.stringDataN);

    return sysname;
}

// cache paramter chunk data
static ipmi_ret_t chunkHandler(uint8_t paraSelector, uint8_t* chunk,
                               uint8_t chunkLen, IpmiSysInfo& info)
{
    uint8_t setSelector;
    static int totalBytes = 0;
    uint8_t validLen = 0;
    uint8_t headerBytes = 0;
    if (NULL == chunk)
    {
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    setSelector = chunk[0];
    std::string s;
    s= "set " + std::to_string(setSelector);
    std::cerr << s << "\n";

    if (setSelector == 0) // chunk0
    {
        info.encoding = chunk[1] & 0xF;
        info.stringLen = chunk[2];
        s = "info.encoding " + std::to_string(info.encoding);
        std::cerr << s << "\n";
        s = "info.stringLen " + std::to_string(info.stringLen);
        std::cerr << s << "\n";
        if (info.stringLen > maxBytesPerParameter)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "exceed max bytes");
            return IPMI_CC_REQ_DATA_LEN_INVALID;
        }
        //info.paramSelector = paraSelector;
        headerBytes = 3;
        totalBytes = 0; // reset counter
    }
    else
    {
        headerBytes = 1;
    }
    s = "chunkLen " + std::to_string(chunkLen);
    std::cerr << s << "\n";
    s = "headerBytes " + std::to_string(headerBytes);
    std::cerr << s << "\n";
    if (chunkLen < headerBytes)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>("invalid length");
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }
    validLen = chunkLen - headerBytes;
    //lookup
    std::memcpy((info.stringDataN + totalBytes), (chunk + headerBytes),
                validLen);
    s= "validLen " + std::to_string(validLen) + "totalBytes " + std::to_string(totalBytes) ;
    std::cerr << s << "\n";
    totalBytes += validLen;

    return IPMI_CC_OK;
}

/**
 * Initialize the systemStore
 * non-volatile paramters are restored from file/storage
 */
static void systemStoreInit()
{
    sysInfoParamStore = std::make_unique<SysInfoParamStore>();
    IpmiSysInfo dummy = {0};
    for (uint8_t paramRequested = IPMI_SYSINFO_SYSTEM_FW_VERSION;
         paramRequested <= IPMI_SYSINFO_OS_HYP_URL; paramRequested++)
    {
        // these 2 are volatile
        if ((paramRequested == IPMI_SYSINFO_OS_VERSION) ||
            (paramRequested == IPMI_SYSINFO_OS_HYP_URL))
        {
            sysInfoParamStore->update(paramRequested, dummy, false);
        }
        else if (IPMI_SYSINFO_SYSTEM_NAME == paramRequested)
        {
            sysInfoParamStore->update(paramRequested, sysInfoReadSystemName);
        }
        else
        { // if fail to restore from file, create empty file
            if (0 != sysInfoParamStore->restore(paramRequested))
            {
                sysInfoParamStore->update(paramRequested, dummy, true);
            }
        }
    }

    for (uint32_t paramRequested = IPMI_SYSINFO_OEM_START;
         paramRequested <= IPMI_SYSINFO_OEM_END; paramRequested++)
    {
        if (0 != sysInfoParamStore->restore((uint8_t)paramRequested))
        {
            sysInfoParamStore->update((uint8_t)paramRequested, dummy, true);
        }
    }
    phosphor::logging::log<phosphor::logging::level::INFO>(
        "systemStoreInit done");
}

ipmi_ret_t ipmi_app_set_system_info(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                    ipmi_request_t request,
                                    ipmi_response_t response,
                                    ipmi_data_len_t dataLen,
                                    ipmi_context_t context)
{
    uint8_t* const reqData = static_cast<uint8_t*>(request);

    constexpr int minRequestSize = 2;
    constexpr int paramSelector = 0;
    constexpr int chunkOffset = 1;
    uint8_t chunkLen = *dataLen - 1;

    const uint8_t paramRequested = reqData[paramSelector];
    uint8_t* chunk = &(reqData[chunkOffset]);
    int rc;
    IpmiSysInfo info;

    if (*dataLen < minRequestSize)
    {
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    *dataLen = 0; // default to 0.
    if (paramRequested == 0)
    {
        // attempt to set the 'set in progress' value (in parameter #0)
        // when not in the set complete state.
        if ((transferStatus != setComplete) &&
            (setInProgress == (chunk[0] & 0x3)))
        {
            return IPMI_CC_SET_IN_PROGRESS_ACTIVE;
        }

        transferStatus = chunk[0] & 0x3;

        return IPMI_CC_OK;
    }

    if (sysInfoParamStore == nullptr)
    {
        systemStoreInit();
    }
    // check chunk data
    rc = chunkHandler(paramRequested, chunk, chunkLen, info);
    if (rc != IPMI_CC_OK)
    {
        return rc;
    }


    // these 2 are volatile
    if ((paramRequested == IPMI_SYSINFO_OS_VERSION) ||
        (paramRequested == IPMI_SYSINFO_OS_HYP_URL))
    {
        sysInfoParamStore->update(paramRequested, info, false);
    }
    else
    {
        sysInfoParamStore->update(paramRequested, info, true);
    }
    return IPMI_CC_OK;
}

ipmi_ret_t ipmi_app_get_system_info(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                    ipmi_request_t request,
                                    ipmi_response_t response,
                                    ipmi_data_len_t dataLen,
                                    ipmi_context_t context)
{
    IpmiSysInfoResp resp = {};
    size_t respLen = 0;
    uint8_t* const reqData = static_cast<uint8_t*>(request);
    IpmiSysInfo param;
    bool found;
    std::tuple<bool, IpmiSysInfo> ret;
    constexpr int minRequestSize = 4;
    constexpr int paramSelector = 1;
    constexpr uint8_t revisionOnly = 0x80;
    const uint8_t paramRequested = reqData[paramSelector];
    int rc;

    if (*dataLen < minRequestSize)
    {
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    *dataLen = 0; // default to 0.

    // Parameters revision as of IPMI spec v2.0 rev. 1.1 (Feb 11, 2014 E6)
    resp.paramRevision = 0x11;
    if (reqData[0] & revisionOnly) // Get parameter revision only
    {
        respLen = 1;
        goto writeResponse;
    }

    // The "Set In Progress" parameter is implemented but rollback is not
    // supported
    if (paramRequested == 0)
    {
        resp.byteData = transferStatus;
        respLen = 2;
        goto writeResponse;
    }

    if (sysInfoParamStore == nullptr)
    {
        systemStoreInit();
    }

    // Parameters other than Set In Progress are assumed to be strings.
    ret = sysInfoParamStore->lookup(paramRequested);
    found = std::get<0>(ret);
    param = std::get<1>(ret);
    if (!found)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "paramter can not found");
        return IPMI_CC_SYSTEM_INFO_PARAMETER_NOT_SUPPORTED;
    }

    rc = packGetSysInfoResp(param, reqData[2], &resp);
    if (rc == -EINVAL)
    {
        return IPMI_CC_RESPONSE_ERROR;
    }

    respLen = sizeof(resp); // Write entire string data chunk in response.

writeResponse:
    std::memcpy(response, &resp, sizeof(resp));
    *dataLen = respLen;
    return IPMI_CC_OK;
}

static int loadI2CWhiteList()
{
    nlohmann::json data = nullptr;
    std::ifstream jsonFile(whiteListFilename);

    if (!jsonFile.good())
    {
        log<level::WARNING>("whitelist file not found!");
        return -1;
    }

    try
    {
        data = nlohmann::json::parse(jsonFile, nullptr, false);
    }
    catch (nlohmann::json::parse_error& e)
    {
        log<level::ERR>("Corrupted whitelist config file",
                        entry("MSG: %s", e.what()));
        return -1;
    }

    try
    {
        unsigned int i = 0;
        nlohmann::json filters = data[filtersStr].get<nlohmann::json>();
        getWhiteList().resize(filters.size());

        for (const auto& it : filters.items())
        {
            nlohmann::json filter = it.value();
            if (filter.is_null())
            {
                log<level::ERR>("Incorrect filter");
                return -1;
            }

            getWhiteList()[i].busId =
                std::stoul(filter[busIdStr].get<std::string>(), nullptr, 16);

            getWhiteList()[i].slaveAddr = std::stoul(
                filter[slaveAddrStr].get<std::string>(), nullptr, 16);

            std::string command = filter[cmdStr].get<std::string>();

            log<level::DEBUG>("IPMI I2C whitelist ", entry("INDEX=%d", i),
                              entry("BUS=%d", getWhiteList()[i].busId),
                              entry("ADDR=0x%x", getWhiteList()[i].slaveAddr),
                              entry("LEN=0x%x", command.length()),
                              entry("COMMAND=[%s]", command.c_str()));

            // convert data string
            std::istringstream iss(command);
            std::string token;
            while (std::getline(iss, token, ' '))
            {
                log<level::DEBUG>("IPMI I2C command\n",
                                  entry("TOKEN=%s", token.c_str()));
                getWhiteList()[i].data.emplace_back(
                    std::stoul(token, nullptr, 16));
            }
            i++;
        }
    }
    catch (std::exception& e)
    {
        log<level::ERR>("unexpected exception", entry("ERROR=%s", e.what()));
        return -1;
    }
    return 0;
}

ipmi_ret_t ipmiMasterWriteRead(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                               ipmi_request_t request, ipmi_response_t response,
                               ipmi_data_len_t data_len, ipmi_context_t context)
{
    bool foundInList = false;
    int ret = 0;
    i2c_rdwr_ioctl_data msgRdwr = {0};
    i2c_msg i2cmsg[2] = {0};
    ipmiI2cRwReq* reqi2c = reinterpret_cast<ipmiI2cRwReq*>(request);

    if (*data_len <= sizeof(ipmiI2cRwReq))
    {
        log<level::ERR>("Failed in request", entry("LEN=%d", *data_len));
        *data_len = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    if (reqi2c->readCount > maxIPMIWriteReadSize)
    {
        log<level::ERR>("Failed in request", entry("R=%d", reqi2c->readCount));
        *data_len = 0;
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    uint8_t* resptr = reinterpret_cast<uint8_t*>(response);
    uint8_t busId = (reqi2c->busId & 0xFF) >> 1;
    // Convert the I2C address from 7-bit format
    uint8_t i2cAddr = reqi2c->slaveAddr >> 1;
    size_t writeCount = *data_len - sizeof(ipmiI2cRwReq);

    log<level::DEBUG>(
        "INPUT: ", entry("LEN=%d", *data_len), entry("ID=0x%x", busId),
        entry("ADDR=0x%x", reqi2c->slaveAddr), entry("R=%d", reqi2c->readCount),
        entry("W=%d", writeCount));

    *data_len = 0;

    std::vector<uint8_t> inBuf(reqi2c->readCount);
    std::vector<uint8_t> outBuf(writeCount);
    uint8_t* reqptr = reinterpret_cast<uint8_t*>(request);

    reqptr += sizeof(ipmiI2cRwReq);
    std::copy(reqptr, reqptr + writeCount, outBuf.begin());

    log<level::DEBUG>("checking list ",
                      entry("SIZE=%d", getWhiteList().size()));
    // command whitelist checking
    for (unsigned int i = 0; i < getWhiteList().size(); i++)
    {
        // TODO add wildchard/regex support
        if ((busId == getWhiteList()[i].busId) &&
            (i2cAddr == getWhiteList()[i].slaveAddr) &&
            (outBuf == getWhiteList()[i].data))
        {
            log<level::DEBUG>("In whitelist");
            foundInList = true;
            break;
        }
    }

    if (!foundInList)
    {
        log<level::ERR>("Request blocked!", entry("BUS=%d", busId),
                        entry("ADDR=0x%x", reqi2c->slaveAddr));
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    log<level::DEBUG>("IPMI Master WriteRead ", entry("BUS=%d", busId),
                      entry("ADDR=0x%x", reqi2c->slaveAddr),
                      entry("R=%d", reqi2c->readCount),
                      entry("W=%d", writeCount));

    std::string i2cBus = "/dev/i2c-" + std::to_string(busId);

    int i2cDev = ::open(i2cBus.c_str(), O_RDWR | O_CLOEXEC);
    if (i2cDev < 0)
    {
        log<level::ERR>("Failed in opening i2c device",
                        entry("BUS=%s", i2cBus.c_str()));
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    // write message
    i2cmsg[0].addr = i2cAddr;
    i2cmsg[0].flags = 0x00;
    i2cmsg[0].len = writeCount;
    i2cmsg[0].buf = outBuf.data();

    // read message
    i2cmsg[1].addr = i2cAddr;
    i2cmsg[1].flags = I2C_M_RD;
    i2cmsg[1].len = reqi2c->readCount;
    i2cmsg[1].buf = inBuf.data();

    msgRdwr.msgs = i2cmsg;
    msgRdwr.nmsgs = 2;

    ret = ::ioctl(i2cDev, I2C_RDWR, &msgRdwr);
    ::close(i2cDev);

    // TODO add completion code support
    if (ret < 0)
    {
        log<level::ERR>("RDWR ioctl error", entry("RET=%d", ret));
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    *data_len = msgRdwr.msgs[1].len;
    std::copy(msgRdwr.msgs[1].buf, msgRdwr.msgs[1].buf + msgRdwr.msgs[1].len,
              resptr);

    return IPMI_CC_OK;
}

void register_netfn_app_functions()
{
    // <Get Device ID>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnApp,
                          ipmi::app::cmdGetDeviceId, ipmi::Privilege::User,
                          ipmiAppGetDeviceId);

    // <Get BT Interface Capabilities>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnApp,
                          ipmi::app::cmdGetBtIfaceCapabilities,
                          ipmi::Privilege::User, ipmiAppGetBtCapabilities);

    // <Reset Watchdog Timer>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnApp,
                          ipmi::app::cmdResetWatchdogTimer,
                          ipmi::Privilege::Operator, ipmiAppResetWatchdogTimer);

    // <Set Watchdog Timer>
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_SET_WD, NULL,
                           ipmi_app_watchdog_set, PRIVILEGE_OPERATOR);

    // <Get Watchdog Timer>
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_GET_WD, NULL,
                           ipmi_app_watchdog_get, PRIVILEGE_OPERATOR);

    // <Get Self Test Results>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnApp,
                          ipmi::app::cmdGetSelfTestResults,
                          ipmi::Privilege::User, ipmiAppGetSelfTestResults);

    // <Get Device GUID>
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_GET_DEVICE_GUID, NULL,
                           ipmi_app_get_device_guid, PRIVILEGE_USER);

    // <Set ACPI Power State>
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_SET_ACPI, NULL,
                           ipmi_app_set_acpi_power_state, PRIVILEGE_ADMIN);

    // <Get ACPI Power State>
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_GET_ACPI, NULL,
                           ipmi_app_get_acpi_power_state, PRIVILEGE_ADMIN);

// TODO: Below code and associated api's need to be removed later.
// Its commented for now to avoid merge conflicts with upstream
// changes and smooth upstream upgrades.
#if 0
>>>>>>> IPMI Channel commands implementation
    // <Get Channel Access>
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_GET_CHANNEL_ACCESS, NULL,
                           ipmi_get_channel_access, PRIVILEGE_USER);

    // <Get Channel Info Command>
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_GET_CHAN_INFO, NULL,
                           ipmi_app_channel_info, PRIVILEGE_USER);
#endif

    int ret = loadI2CWhiteList();
    log<level::DEBUG>("i2c white list is loaded", entry("RET=%d", ret),
                      entry("SIZE=%d", getWhiteList().size()));
    if (ret == 0)
    {
        log<level::DEBUG>("Register Master RW command");
        // <Master Write Read Command>
        ipmi_register_callback(NETFUN_APP, IPMI_CMD_MASTER_WRITE_READ, NULL,
                               ipmiMasterWriteRead, PRIVILEGE_OPERATOR);
    }

    // <Get System GUID Command>
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_GET_SYS_GUID, NULL,
                           ipmi_app_get_sys_guid, PRIVILEGE_USER);

    // <Get Channel Cipher Suites Command>
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_GET_CHAN_CIPHER_SUITES, NULL,
                           getChannelCipherSuites, PRIVILEGE_CALLBACK);

    // <Set System Info Command>
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_SET_SYSTEM_INFO, NULL,
                           ipmi_app_set_system_info, PRIVILEGE_USER);
    // <Get System Info Command>
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_GET_SYSTEM_INFO, NULL,
                           ipmi_app_get_system_info, PRIVILEGE_USER);
    return;
}
