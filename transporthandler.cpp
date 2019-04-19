#include "transporthandler.hpp"

#include "app/channel.hpp"
#include "user_channel/channel_layer.hpp"

#include <arpa/inet.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <ipmid/api.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/message/types.hpp>
#include <sdbusplus/timer.hpp>
#include <string>
#include <xyz/openbmc_project/Common/error.hpp>

#define SYSTEMD_NETWORKD_DBUS 1

#ifdef SYSTEMD_NETWORKD_DBUS
#include <mapper.h>
#include <systemd/sd-bus.h>
#endif

// timer for network changes
std::unique_ptr<phosphor::Timer> networkTimer = nullptr;

const int SIZE_MAC = 18; // xx:xx:xx:xx:xx:xx
constexpr auto ipv4Protocol = "xyz.openbmc_project.Network.IP.Protocol.IPv4";
constexpr auto ipv6Protocol = "xyz.openbmc_project.Network.IP.Protocol.IPv6";

static const std::array<std::string, 3> ipAddressEnablesType = {
    "xyz.openbmc_project.Network.EthernetInterface.IPAllowed.IPv4Only",
    "xyz.openbmc_project.Network.EthernetInterface.IPAllowed.IPv6Only",
    "xyz.openbmc_project.Network.EthernetInterface.IPAllowed.IPv4AndIPv6"};

constexpr const char* solInterface = "xyz.openbmc_project.Ipmi.SOL";
constexpr const char* solPath = "/xyz/openbmc_project/ipmi/sol";

std::map<int, std::unique_ptr<struct ChannelConfig_t>> channelConfig;

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;

namespace fs = std::filesystem;
namespace variant_ns = sdbusplus::message::variant_ns;

void register_netfn_transport_functions() __attribute__((constructor));

struct ChannelConfig_t* getChannelConfig(int channel)
{
    auto item = channelConfig.find(channel);
    if (item == channelConfig.end())
    {
        channelConfig[channel] = std::make_unique<struct ChannelConfig_t>();
    }

    return channelConfig[channel].get();
}

// Helper Function to get IP Address/NetMask/Gateway/MAC Address from Network
// Manager or Cache based on Set-In-Progress State
ipmi_ret_t getNetworkData(uint8_t lan_param, uint8_t* data, int channel)
{
    ipmi_ret_t rc = IPMI_CC_OK;
    sdbusplus::bus::bus bus(ipmid_get_sd_bus_connection());

    auto ethdevice = ipmi::getChannelName(channel);
    // if ethdevice is an empty string they weren't expecting this channel.
    if (ethdevice.empty())
    {
        // TODO: return error from getNetworkData()
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }
    auto ethIP = ethdevice + "/" + ipmi::network::IP_TYPE;
    auto channelConf = getChannelConfig(channel);

    try
    {
        switch (static_cast<LanParam>(lan_param))
        {
            case LanParam::IP:
            {
                std::string ipaddress;
                if (channelConf->lan_set_in_progress == SET_COMPLETE)
                {
                    try
                    {
                        auto ipObjectInfo =
                            ipmi::getIPObject(bus, ipmi::network::IP_INTERFACE,
                                              ipmi::network::ROOT, ethIP);

                        auto properties = ipmi::getAllDbusProperties(
                            bus, ipObjectInfo.second, ipObjectInfo.first,
                            ipmi::network::IP_INTERFACE);

                        ipaddress =
                            variant_ns::get<std::string>(properties["Address"]);
                    }
                    // ignore the exception, as it is a valid condition that
                    // the system is not configured with any IP.
                    catch (InternalFailure& e)
                    {
                        // nothing to do.
                    }
                }
                else if (channelConf->lan_set_in_progress == SET_IN_PROGRESS)
                {
                    ipaddress = channelConf->ipaddr;
                }

                inet_pton(AF_INET, ipaddress.c_str(),
                          reinterpret_cast<void*>(data));
            }
            break;

            case LanParam::IPSRC:
            {
                std::string networkInterfacePath;

                if (channelConf->lan_set_in_progress == SET_COMPLETE)
                {
                    try
                    {
                        ipmi::ObjectTree ancestorMap;
                        // if the system is having ip object,then
                        // get the IP object.
                        auto ipObject = ipmi::getDbusObject(
                            bus, ipmi::network::IP_INTERFACE,
                            ipmi::network::ROOT, ethIP);

                        // Get the parent interface of the IP object.
                        try
                        {
                            ipmi::InterfaceList interfaces;
                            interfaces.emplace_back(
                                ipmi::network::ETHERNET_INTERFACE);

                            ancestorMap = ipmi::getAllAncestors(
                                bus, ipObject.first, std::move(interfaces));
                        }
                        catch (InternalFailure& e)
                        {
                            // if unable to get the parent interface
                            // then commit the error and return.
                            log<level::ERR>(
                                "Unable to get the parent interface",
                                entry("PATH=%s", ipObject.first.c_str()),
                                entry("INTERFACE=%s",
                                      ipmi::network::ETHERNET_INTERFACE));
                            break;
                        }
                        // for an ip object there would be single parent
                        // interface.
                        networkInterfacePath = ancestorMap.begin()->first;
                    }
                    catch (InternalFailure& e)
                    {
                        // if there is no ip configured on the system,then
                        // get the network interface object.
                        auto networkInterfaceObject = ipmi::getDbusObject(
                            bus, ipmi::network::ETHERNET_INTERFACE,
                            ipmi::network::ROOT, ethdevice);

                        networkInterfacePath = networkInterfaceObject.first;
                    }

                    auto variant = ipmi::getDbusProperty(
                        bus, ipmi::network::SERVICE, networkInterfacePath,
                        ipmi::network::ETHERNET_INTERFACE, "DHCPEnabled");

                    auto dhcpEnabled = variant_ns::get<bool>(variant);
                    // As per IPMI spec 2=>DHCP, 1=STATIC
                    auto ipsrc = dhcpEnabled ? ipmi::network::IPOrigin::DHCP
                                             : ipmi::network::IPOrigin::STATIC;

                    std::memcpy(data, &ipsrc, ipmi::network::IPSRC_SIZE_BYTE);
                }
                else if (channelConf->lan_set_in_progress == SET_IN_PROGRESS)
                {
                    std::memcpy(data, &(channelConf->ipsrc),
                                ipmi::network::IPSRC_SIZE_BYTE);
                }
            }
            break;

            case LanParam::SUBNET:
            {
                unsigned long mask{};
                if (channelConf->lan_set_in_progress == SET_COMPLETE)
                {
                    try
                    {
                        auto ipObjectInfo =
                            ipmi::getIPObject(bus, ipmi::network::IP_INTERFACE,
                                              ipmi::network::ROOT, ethIP);

                        auto properties = ipmi::getAllDbusProperties(
                            bus, ipObjectInfo.second, ipObjectInfo.first,
                            ipmi::network::IP_INTERFACE);

                        auto prefix = variant_ns::get<uint8_t>(
                            properties["PrefixLength"]);
                        mask = ipmi::network::MASK_32_BIT;
                        mask = htonl(mask << (ipmi::network::BITS_32 - prefix));
                    }
                    // ignore the exception, as it is a valid condition that
                    // the system is not configured with any IP.
                    catch (InternalFailure& e)
                    {
                        // nothing to do
                    }
                    std::memcpy(data, &mask,
                                ipmi::network::IPV4_ADDRESS_SIZE_BYTE);
                }
                else if (channelConf->lan_set_in_progress == SET_IN_PROGRESS)
                {
                    inet_pton(AF_INET, channelConf->netmask.c_str(),
                              reinterpret_cast<void*>(data));
                }
            }
            break;

            case LanParam::GATEWAY:
            {
                std::string gateway;

                if (channelConf->lan_set_in_progress == SET_COMPLETE)
                {
                    try
                    {
                        auto systemObject = ipmi::getDbusObject(
                            bus, ipmi::network::SYSTEMCONFIG_INTERFACE,
                            ipmi::network::ROOT);

                        auto systemProperties = ipmi::getAllDbusProperties(
                            bus, systemObject.second, systemObject.first,
                            ipmi::network::SYSTEMCONFIG_INTERFACE);

                        gateway = variant_ns::get<std::string>(
                            systemProperties["DefaultGateway"]);
                    }
                    // ignore the exception, as it is a valid condition that
                    // the system is not configured with any IP.
                    catch (InternalFailure& e)
                    {
                        // nothing to do
                    }
                }
                else if (channelConf->lan_set_in_progress == SET_IN_PROGRESS)
                {
                    gateway = channelConf->gateway;
                }

                inet_pton(AF_INET, gateway.c_str(),
                          reinterpret_cast<void*>(data));
            }
            break;

            case LanParam::MAC:
            {
                std::string macAddress;
                if (channelConf->lan_set_in_progress == SET_COMPLETE)
                {
                    auto macObjectInfo =
                        ipmi::getDbusObject(bus, ipmi::network::MAC_INTERFACE,
                                            ipmi::network::ROOT, ethdevice);

                    auto variant = ipmi::getDbusProperty(
                        bus, macObjectInfo.second, macObjectInfo.first,
                        ipmi::network::MAC_INTERFACE, "MACAddress");

                    macAddress = variant_ns::get<std::string>(variant);
                }
                else if (channelConf->lan_set_in_progress == SET_IN_PROGRESS)
                {
                    macAddress = channelConf->macAddress;
                }

                sscanf(macAddress.c_str(), ipmi::network::MAC_ADDRESS_FORMAT,
                       (data), (data + 1), (data + 2), (data + 3), (data + 4),
                       (data + 5));
            }
            break;

            case LanParam::VLAN:
            {
                uint16_t vlanID{};
                if (channelConf->lan_set_in_progress == SET_COMPLETE)
                {
                    try
                    {
                        auto ipObjectInfo = ipmi::getIPObject(
                            bus, ipmi::network::IP_INTERFACE,
                            ipmi::network::ROOT, ipmi::network::IP_TYPE);

                        vlanID = static_cast<uint16_t>(
                            ipmi::network::getVLAN(ipObjectInfo.first));

                        vlanID = htole16(vlanID);

                        if (vlanID)
                        {
                            // Enable the 16th bit
                            vlanID |= htole16(ipmi::network::VLAN_ENABLE_MASK);
                        }
                    }
                    // ignore the exception, as it is a valid condition that
                    // the system is not configured with any IP.
                    catch (InternalFailure& e)
                    {
                        // nothing to do
                    }

                    std::memcpy(data, &vlanID, ipmi::network::VLAN_SIZE_BYTE);
                }
                else if (channelConf->lan_set_in_progress == SET_IN_PROGRESS)
                {
                    std::memcpy(data, &(channelConf->vlanID),
                                ipmi::network::VLAN_SIZE_BYTE);
                }
            }
            break;

            default:
                rc = IPMI_CC_PARM_OUT_OF_RANGE;
        }
    }
    catch (InternalFailure& e)
    {
        commit<InternalFailure>();
        rc = IPMI_CC_UNSPECIFIED_ERROR;
        return rc;
    }
    return rc;
}

namespace cipher
{

std::vector<uint8_t> getCipherList()
{
    std::vector<uint8_t> cipherList;

    std::ifstream jsonFile(configFile);
    if (!jsonFile.is_open())
    {
        log<level::ERR>("Channel Cipher suites file not found");
        elog<InternalFailure>();
    }

    auto data = Json::parse(jsonFile, nullptr, false);
    if (data.is_discarded())
    {
        log<level::ERR>("Parsing channel cipher suites JSON failed");
        elog<InternalFailure>();
    }

    // Byte 1 is reserved
    cipherList.push_back(0x00);

    for (const auto& record : data)
    {
        cipherList.push_back(record.value(cipher, 0));
    }

    return cipherList;
}

} // namespace cipher

ipmi_ret_t ipmi_transport_wildcard(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                   ipmi_request_t request,
                                   ipmi_response_t response,
                                   ipmi_data_len_t data_len,
                                   ipmi_context_t context)
{
    // Status code.
    ipmi_ret_t rc = IPMI_CC_INVALID;
    *data_len = 0;
    return rc;
}

struct set_lan_t
{
    uint8_t channel;
    uint8_t parameter;
    uint8_t data[8]; // Per IPMI spec, not expecting more than this size
} __attribute__((packed));

ipmi_ret_t checkAndUpdateNetwork(int channel)
{
    auto channelConf = getChannelConfig(channel);
    using namespace std::chrono_literals;
    // time to wait before applying the network changes.
    constexpr auto networkTimeout = 10000000us; // 10 sec

    // Skip the timer. Expecting more update as we are in SET_IN_PROGRESS
    if (channelConf->lan_set_in_progress == SET_IN_PROGRESS)
    {
        return IPMI_CC_OK;
    }

    // Start the timer, if it is direct single param update without
    // SET_IN_PROGRESS or many params updated through SET_IN_PROGRESS to
    // SET_COMPLETE Note: Even for update with SET_IN_PROGRESS, don't apply the
    // changes immediately, as ipmitool sends each param individually
    // through SET_IN_PROGRESS to SET_COMPLETE.
    channelConf->flush = true;
    if (!networkTimer)
    {
        log<level::ERR>("Network timer is not instantiated");
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    // start the timer.
    networkTimer->start(networkTimeout);
    return IPMI_CC_OK;
}

ipmi_ret_t ipmi_transport_set_lan(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                  ipmi_request_t request,
                                  ipmi_response_t response,
                                  ipmi_data_len_t data_len,
                                  ipmi_context_t context)
{
    ipmi_ret_t rc = IPMI_CC_OK;

    char ipaddr[INET_ADDRSTRLEN];
    char netmask[INET_ADDRSTRLEN];
    char gateway[INET_ADDRSTRLEN];

    auto reqptr = reinterpret_cast<const set_lan_t*>(request);
    sdbusplus::bus::bus bus(ipmid_get_sd_bus_connection());

    size_t reqLen = *data_len;
    *data_len = 0;

    // channel number is the lower nibble
    int channel = reqptr->channel & CHANNEL_MASK;
    auto ethdevice = ipmi::getChannelName(channel);
    if (ethdevice.empty())
    {
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }
    auto channelConf = getChannelConfig(channel);

    switch (static_cast<LanParam>(reqptr->parameter))
    {
        case LanParam::IP:
        {
            std::snprintf(ipaddr, INET_ADDRSTRLEN,
                          ipmi::network::IP_ADDRESS_FORMAT, reqptr->data[0],
                          reqptr->data[1], reqptr->data[2], reqptr->data[3]);

            channelConf->ipaddr.assign(ipaddr);
        }
        break;

        case LanParam::IPSRC:
        {
            if (reqLen != LAN_PARAM_IPSRC_SIZE)
            {
                return IPMI_CC_REQ_DATA_LEN_INVALID;
            }

            uint8_t ipsrc{};
            std::memcpy(&ipsrc, reqptr->data, ipmi::network::IPSRC_SIZE_BYTE);
            channelConf->ipsrc = static_cast<ipmi::network::IPOrigin>(ipsrc);
        }
        break;

        case LanParam::MAC:
        {
            if (reqLen != LAN_PARAM_MAC_SIZE)
            {
                return IPMI_CC_REQ_DATA_LEN_INVALID;
            }

            char mac[SIZE_MAC];

            std::snprintf(mac, SIZE_MAC, ipmi::network::MAC_ADDRESS_FORMAT,
                          reqptr->data[0], reqptr->data[1], reqptr->data[2],
                          reqptr->data[3], reqptr->data[4], reqptr->data[5]);

            auto macObjectInfo =
                ipmi::getDbusObject(bus, ipmi::network::MAC_INTERFACE,
                                    ipmi::network::ROOT, ethdevice);

            ipmi::setDbusProperty(
                bus, macObjectInfo.second, macObjectInfo.first,
                ipmi::network::MAC_INTERFACE, "MACAddress", std::string(mac));

            channelConf->macAddress = mac;
        }
        break;

        case LanParam::SUBNET:
        {
            if (reqLen != LAN_PARAM_SUBNET_SIZE)
            {
                return IPMI_CC_REQ_DATA_LEN_INVALID;
            }

            std::snprintf(netmask, INET_ADDRSTRLEN,
                          ipmi::network::IP_ADDRESS_FORMAT, reqptr->data[0],
                          reqptr->data[1], reqptr->data[2], reqptr->data[3]);
            channelConf->netmask.assign(netmask);
        }
        break;

        case LanParam::GATEWAY:
        {
            if (reqLen != LAN_PARAM_GATEWAY_SIZE)
            {
                return IPMI_CC_REQ_DATA_LEN_INVALID;
            }

            std::snprintf(gateway, INET_ADDRSTRLEN,
                          ipmi::network::IP_ADDRESS_FORMAT, reqptr->data[0],
                          reqptr->data[1], reqptr->data[2], reqptr->data[3]);
            channelConf->gateway.assign(gateway);
        }
        break;

        case LanParam::VLAN:
        {
            if (reqLen != LAN_PARAM_VLAN_SIZE)
            {
                return IPMI_CC_REQ_DATA_LEN_INVALID;
            }

            uint16_t vlan{};
            std::memcpy(&vlan, reqptr->data, ipmi::network::VLAN_SIZE_BYTE);
            // We are not storing the enable bit
            // We assume that ipmitool always send enable
            // bit as 1.
            vlan = le16toh(vlan);
            channelConf->vlanID = vlan;
        }
        break;

        case LanParam::INPROGRESS:
        {
            if (reqLen != LAN_PARAM_INPROGRESS_SIZE)
            {
                return IPMI_CC_REQ_DATA_LEN_INVALID;
            }

            if (reqptr->data[0] == SET_COMPLETE)
            {
                channelConf->lan_set_in_progress = SET_COMPLETE;

                log<level::INFO>(
                    "Network data from Cache",
                    entry("PREFIX=%s", channelConf->netmask.c_str()),
                    entry("ADDRESS=%s", channelConf->ipaddr.c_str()),
                    entry("GATEWAY=%s", channelConf->gateway.c_str()),
                    entry("VLAN=%d", channelConf->vlanID));
            }
            else if (reqptr->data[0] == SET_IN_PROGRESS) // Set In Progress
            {
                channelConf->lan_set_in_progress = SET_IN_PROGRESS;
            }
        }
        break;

        case LanParam::IPV6_AND_IPV4_ENABLES:
        {
            if (reqLen != LAN_PARAM_IPV6_AND_IPV4_ENABLES_SIZE)
            {
                return IPMI_CC_REQ_DATA_LEN_INVALID;
            }

            channelConf->ipv6AddressingEnables = reqptr->data[0];
            break;
        }

        case LanParam::IPV6_STATIC_ADDRESSES:
        {
            if (reqLen != LAN_PARAM_IPV6_STATIC_ADDRESSES_SIZE)
            {
                return IPMI_CC_REQ_DATA_LEN_INVALID;
            }

            channelConf->ipv6AddressSource =
                reqptr->data[1] & 0x81; // Looking at bit 0 and bit 7
            char tmpIPV6[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &reqptr->data[2], tmpIPV6, INET6_ADDRSTRLEN);
            channelConf->ipv6Addr.assign(tmpIPV6);
            channelConf->ipv6Prefix = reqptr->data[19];
            break;
        }

        case LanParam::IPV6_ROUTER_ADDRESS_CONF_CTRL:
        {
            if (reqLen != LAN_PARAM_IPV6_ROUTER_ADDRESS_CONF_CTRL_SIZE)
            {
                return IPMI_CC_REQ_DATA_LEN_INVALID;
            }

            channelConf->ipv6RouterAddressConfigControl = reqptr->data[0];
            break;
        }

        case LanParam::IPV6_STATIC_ROUTER_1_IP_ADDR:
        {
            if (reqLen != LAN_PARAM_IPV6_STATIC_ROUTER_1_IP_ADDR_SIZE)
            {
                return IPMI_CC_REQ_DATA_LEN_INVALID;
            }

            char tmpIPV6[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, reinterpret_cast<const void*>(reqptr->data),
                      tmpIPV6, INET6_ADDRSTRLEN);
            channelConf->ipv6GatewayAddr.assign(tmpIPV6);
            break;
        }

        case LanParam::IPV6_STATIC_ROUTER_1_PREFIX_LEN:
        {
            if (reqLen != LAN_PARAM_IPV6_STATIC_ROUTER_1_PREFIX_LEN_SIZE)
            {
                return IPMI_CC_REQ_DATA_LEN_INVALID;
            }

            channelConf->ipv6GatewayPrefixLength = reqptr->data[0];
            break;
        }

        case LanParam::IPV6_STATIC_ROUTER_1_PREFIX_VAL:
        {
            if (reqLen != LAN_PARAM_IPV6_STATIC_ROUTER_1_PREFIX_VAL_SIZE)
            {
                return IPMI_CC_REQ_DATA_LEN_INVALID;
            }

            char tmpIPV6[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, reinterpret_cast<const void*>(reqptr->data),
                      tmpIPV6, INET6_ADDRSTRLEN);
            channelConf->ipv6GatewayPrefixValue.assign(tmpIPV6);
            break;
        }

        case LanParam::IPV6_STATIC_ROUTER_2_IP_ADDR:
        {
            if (reqLen != LAN_PARAM_IPV6_STATIC_ROUTER_2_IP_ADDR_SIZE)
            {
                return IPMI_CC_REQ_DATA_LEN_INVALID;
            }

            char tmpIPV6[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, reinterpret_cast<const void*>(reqptr->data),
                      tmpIPV6, INET6_ADDRSTRLEN);
            channelConf->ipv6BackupGatewayAddr.assign(tmpIPV6);
            break;
        }

        case LanParam::IPV6_STATIC_ROUTER_2_PREFIX_LEN:
        {
            if (reqLen != LAN_PARAM_IPV6_STATIC_ROUTER_2_PREFIX_LEN_SIZE)
            {
                return IPMI_CC_REQ_DATA_LEN_INVALID;
            }

            channelConf->ipv6BackupGatewayPrefixLength = reqptr->data[0];
            break;
        }

        case LanParam::IPV6_STATIC_ROUTER_2_PREFIX_VAL:
        {
            if (reqLen != LAN_PARAM_IPV6_STATIC_ROUTER_2_PREFIX_VAL_SIZE)
            {
                return IPMI_CC_REQ_DATA_LEN_INVALID;
            }

            char tmpIPV6[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, reinterpret_cast<const void*>(reqptr->data),
                      tmpIPV6, INET6_ADDRSTRLEN);
            channelConf->ipv6BackupGatewayPrefixValue.assign(tmpIPV6);
            break;
        }

        default:
        {
            rc = IPMI_CC_PARM_NOT_SUPPORTED;
            return rc;
        }
    }
    rc = checkAndUpdateNetwork(channel);

    return rc;
}

struct get_lan_t
{
    uint8_t rev_channel;
    uint8_t parameter;
    uint8_t parameter_set;
    uint8_t parameter_block;
} __attribute__((packed));

ipmi_ret_t ipmi_transport_get_lan(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                  ipmi_request_t request,
                                  ipmi_response_t response,
                                  ipmi_data_len_t data_len,
                                  ipmi_context_t context)
{
    ipmi_ret_t rc = IPMI_CC_OK;
    *data_len = 0;
    const uint8_t current_revision = 0x11; // Current rev per IPMI Spec 2.0
    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};

    get_lan_t* reqptr = (get_lan_t*)request;
    // channel number is the lower nibble
    int channel = reqptr->rev_channel & CHANNEL_MASK;

    if (reqptr->rev_channel & 0x80) // Revision is bit 7
    {
        // Only current revision was requested
        *data_len = sizeof(current_revision);
        std::memcpy(response, &current_revision, *data_len);
        return IPMI_CC_OK;
    }

    static std::vector<uint8_t> cipherList;
    static auto listInit = false;

    if (!listInit)
    {
        try
        {
            cipherList = cipher::getCipherList();
            listInit = true;
        }
        catch (const std::exception& e)
        {
            return IPMI_CC_UNSPECIFIED_ERROR;
        }
    }

    auto ethdevice = ipmi::getChannelName(channel);
    if (ethdevice.empty())
    {
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }
    auto channelConf = getChannelConfig(channel);

    LanParam param = static_cast<LanParam>(reqptr->parameter);
    switch (param)
    {
        case LanParam::INPROGRESS:
        {
            uint8_t buf[] = {current_revision,
                             channelConf->lan_set_in_progress};
            *data_len = sizeof(buf);
            std::memcpy(response, &buf, *data_len);
            break;
        }
        case LanParam::AUTHSUPPORT:
        {
            uint8_t buf[] = {current_revision, 0x04};
            *data_len = sizeof(buf);
            std::memcpy(response, &buf, *data_len);
            break;
        }
        case LanParam::AUTHENABLES:
        {
            uint8_t buf[] = {current_revision, 0x04, 0x04, 0x04, 0x04, 0x04};
            *data_len = sizeof(buf);
            std::memcpy(response, &buf, *data_len);
            break;
        }
        case LanParam::IP:
        case LanParam::SUBNET:
        case LanParam::GATEWAY:
        case LanParam::MAC:
        {
            uint8_t buf[ipmi::network::MAC_ADDRESS_SIZE_BYTE + 1] = {};

            *data_len = sizeof(current_revision);
            std::memcpy(buf, &current_revision, *data_len);

            if (getNetworkData(reqptr->parameter, &buf[1], channel) ==
                IPMI_CC_OK)
            {
                if (param == LanParam::MAC)
                {
                    *data_len = sizeof(buf);
                }
                else
                {
                    *data_len = ipmi::network::IPV4_ADDRESS_SIZE_BYTE + 1;
                }
                std::memcpy(response, &buf, *data_len);
            }
            else
            {
                rc = IPMI_CC_UNSPECIFIED_ERROR;
            }
            break;
        }
        case LanParam::VLAN:
        {
            uint8_t buf[ipmi::network::VLAN_SIZE_BYTE + 1] = {};

            *data_len = sizeof(current_revision);
            std::memcpy(buf, &current_revision, *data_len);
            if (getNetworkData(reqptr->parameter, &buf[1], channel) ==
                IPMI_CC_OK)
            {
                *data_len = sizeof(buf);
                std::memcpy(response, &buf, *data_len);
            }
            break;
        }
        case LanParam::IPSRC:
        {
            uint8_t buff[ipmi::network::IPSRC_SIZE_BYTE + 1] = {};
            *data_len = sizeof(current_revision);
            std::memcpy(buff, &current_revision, *data_len);
            if (getNetworkData(reqptr->parameter, &buff[1], channel) ==
                IPMI_CC_OK)
            {
                *data_len = sizeof(buff);
                std::memcpy(response, &buff, *data_len);
            }
            break;
        }
        case LanParam::CIPHER_SUITE_COUNT:
        {
            *(static_cast<uint8_t*>(response)) = current_revision;
            // Byte 1 is reserved byte and does not indicate a cipher suite ID,
            // so no of cipher suite entry count is one less than the size of
            // the vector
            auto count = static_cast<uint8_t>(cipherList.size() - 1);
            *(static_cast<uint8_t*>(response) + 1) = count;
            *data_len = sizeof(current_revision) + sizeof(count);
            break;
        }
        case LanParam::CIPHER_SUITE_ENTRIES:
        {
            *(static_cast<uint8_t*>(response)) = current_revision;
            // Byte 1 is reserved
            std::copy_n(cipherList.data(), cipherList.size(),
                        static_cast<uint8_t*>(response) + 1);
            *data_len = sizeof(current_revision) +
                        static_cast<uint8_t>(cipherList.size());
            break;
        }
        case LanParam::IPV6_AND_IPV4_SUPPORTED:
        {
            uint8_t addressSupport =
                0x1; // Allow both IPv4 & IPv6 simultaneously
            std::array<uint8_t, 2> buf = {current_revision, addressSupport};
            std::copy(buf.begin(), buf.end(), static_cast<uint8_t*>(response));
            *data_len = buf.size();
            break;
        }
        case LanParam::IPV6_AND_IPV4_ENABLES:
        {
            // If DHCP, check if you have an ipv6 and ipv4 address. If static
            // return not supported

            // 00h check if conf DHCP == ipv4 or off
            // 01h check if conf DHCP == ipv6
            // 02h check if DHCP == true

            auto ethIP = ethdevice + "/" + ipmi::network::IPV6_TYPE;
            std::string networkInterfacePath;
            uint8_t ipVAddressEnables = 0;

            if (channelConf->lan_set_in_progress == SET_COMPLETE)
            {
                try
                {
                    ipmi::ObjectTree ancestorMap;
                    // if the system has an ip object,then
                    // get the IP object.
                    auto ipObject =
                        ipmi::getDbusObject(bus, ipmi::network::IP_INTERFACE,
                                            ipmi::network::ROOT, ethIP);
                    // Get the parent interface of the IP object.
                    try
                    {
                        ipmi::InterfaceList interfaces;
                        interfaces.emplace_back(
                            ipmi::network::ETHERNET_INTERFACE);

                        ancestorMap = ipmi::getAllAncestors(
                            bus, ipObject.first, std::move(interfaces));
                    }
                    catch (InternalFailure& e)
                    {
                        // if unable to get the parent interface
                        // then commit the error and return.
                        log<level::ERR>(
                            "Unable to get the parent interface",
                            entry("PATH=%s", ipObject.first.c_str()),
                            entry("INTERFACE=%s",
                                  ipmi::network::ETHERNET_INTERFACE));
                        return IPMI_CC_UNSPECIFIED_ERROR;
                    }
                    // for an ip object there would be single parent
                    // interface.
                    networkInterfacePath = ancestorMap.begin()->first;
                }
                catch (InternalFailure& e)
                {
                    // if there is no ip configured on the system,then
                    // get the network interface object.
                    auto networkInterfaceObject = ipmi::getDbusObject(
                        bus, ipmi::network::ETHERNET_INTERFACE,
                        ipmi::network::ROOT, ethdevice);

                    networkInterfacePath = networkInterfaceObject.first;
                }

                ipmi::Value ipEnablesProp = ipmi::getDbusProperty(
                    bus, ipmi::network::SERVICE, networkInterfacePath,
                    ipmi::network::ETHERNET_INTERFACE, "IPAddressEnables");
                std::string ipEnables = std::get<std::string>(ipEnablesProp);

                // check if on off ipv4 ipv6, etc.
                bool found = false;
                for (uint8_t ii = 0; ii < ipAddressEnablesType.size(); ii++)
                {
                    if (ipEnables == ipAddressEnablesType[ii])
                    {
                        ipVAddressEnables = ii;
                        found = true;
                        break;
                    }
                }
                if (!found)
                {
                    return IPMI_CC_PARM_NOT_SUPPORTED;
                }
            }
            else
            {
                ipVAddressEnables = channelConf->ipv6AddressingEnables;
            }

            std::array<uint8_t, 2> buf = {current_revision, ipVAddressEnables};
            std::copy(buf.begin(), buf.end(), static_cast<uint8_t*>(response));
            *data_len = buf.size();
            break;
        }
        case LanParam::IPV6_STATUS:
        {
            // Number of IPV6 addresses that are supported
            constexpr std::array<uint8_t, 3> statusData = {1, 1, 3};

            std::array<uint8_t, 4> buf = {current_revision, statusData[0],
                                          statusData[1], statusData[2]};
            std::copy(buf.begin(), buf.end(), static_cast<uint8_t*>(response));
            *data_len = buf.size();
            break;
        }
        case LanParam::IPV6_STATIC_ADDRESSES:
        {
            // Only return set selector 0
            uint8_t ipv6SetSelector = 0;
            std::string ipaddress;
            auto ethIP = ethdevice + "/" + ipmi::network::IPV6_TYPE;
            uint8_t ipv6AddressSource = 0;
            uint8_t prefixLength = 0;
            uint8_t status = 0;
            if (channelConf->lan_set_in_progress == SET_COMPLETE)
            {
                try
                {
                    auto ipObjectInfo =
                        ipmi::getIPObject(bus, ipmi::network::IP_INTERFACE,
                                          ipmi::network::ROOT, ethIP);

                    auto properties = ipmi::getAllDbusProperties(
                        bus, ipObjectInfo.second, ipObjectInfo.first,
                        ipmi::network::IP_INTERFACE);

                    if (std::get<std::string>(properties["Origin"]) ==
                        "xyz.openbmc_project.Network.IP.AddressOrigin.Static")
                    {
                        ipaddress =
                            std::get<std::string>(properties["Address"]);
                        ipv6AddressSource = 0x81; // Looking at bit 0 and bit 7
                        prefixLength =
                            std::get<uint8_t>(properties["PrefixLength"]);
                        status = 0;
                    }
                }
                // ignore the exception, as it is a valid condition that
                // the system is not configured with any IP.
                catch (InternalFailure& e)
                {
                    // nothing to do.
                }
            }
            else if (channelConf->lan_set_in_progress == SET_IN_PROGRESS)
            {
                ipv6AddressSource = channelConf->ipv6AddressSource;
                ipaddress = channelConf->ipv6Addr.c_str();
                prefixLength = channelConf->ipv6Prefix;
                status = 1;
            }

            std::array<uint8_t, ipmi::network::IPV6_ADDRESS_STATUS_SIZE> buf = {
                current_revision, ipv6SetSelector, ipv6AddressSource};
            inet_pton(AF_INET6, ipaddress.c_str(),
                      reinterpret_cast<void*>(&buf[3]));
            buf[20] = prefixLength;
            buf[21] = status;

            std::copy(buf.begin(), buf.end(), static_cast<uint8_t*>(response));
            *data_len = buf.size();
            break;
        }
        case LanParam::IPV6_DHCPV6_STATIC_DUID_STORAGE_LENGTH:
        {
            // DHCP unique identified
            // Only 1 read-only 16-byte Block needed
            uint8_t duidLength = 1;
            std::array<uint8_t, 2> buf = {current_revision, duidLength};
            std::copy(buf.begin(), buf.end(), static_cast<uint8_t*>(response));
            *data_len = buf.size();
            break;
        }
        case LanParam::IPV6_DHCPV6_STATIC_DUIDS:
        {
            std::string macAddress;
            if (channelConf->lan_set_in_progress == SET_COMPLETE)
            {
                auto macObjectInfo =
                    ipmi::getDbusObject(bus, ipmi::network::MAC_INTERFACE,
                                        ipmi::network::ROOT, ethdevice);

                auto variant = ipmi::getDbusProperty(
                    bus, macObjectInfo.second, macObjectInfo.first,
                    ipmi::network::MAC_INTERFACE, "MACAddress");

                macAddress = std::get<std::string>(variant);
            }
            else if (channelConf->lan_set_in_progress == SET_IN_PROGRESS)
            {
                macAddress = channelConf->macAddress;
            }

            std::array<uint8_t,
                       ipmi::network::IPV6_DUID_SIZE + sizeof(current_revision)>
                buf;
            buf = {current_revision,
                   reqptr->parameter_set,
                   reqptr->parameter_block,
                   DUID_LEN,
                   0, // Filler byte
                   DUID_LL_TYPE,
                   0, // Filler byte
                   DUIC_ETH_HW_TYPE};
            sscanf(macAddress.c_str(), ipmi::network::MAC_ADDRESS_FORMAT,
                   (&buf[8]), (&buf[9]), (&buf[10]), (&buf[11]), (&buf[12]),
                   (&buf[13]));

            std::copy(buf.begin(), buf.end(), static_cast<uint8_t*>(response));
            *data_len = buf.size();
            break;
        }
        case LanParam::IPV6_DYNAMIC_ADDRESSES:
        {
            std::string ipaddress;
            uint8_t ipv6AddressSource = 0;
            uint8_t prefixLength = 0;
            uint8_t status = 0;
            auto ethIP = ethdevice + "/" + ipmi::network::IPV6_TYPE;

            if (channelConf->lan_set_in_progress == SET_COMPLETE)
            {
                try
                {
                    auto ipObjectInfo =
                        ipmi::getIPObject(bus, ipmi::network::IP_INTERFACE,
                                          ipmi::network::ROOT, ethIP);

                    auto properties = ipmi::getAllDbusProperties(
                        bus, ipObjectInfo.second, ipObjectInfo.first,
                        ipmi::network::IP_INTERFACE);

                    if (std::get<std::string>(properties["Origin"]) ==
                        "xyz.openbmc_project.Network.IP.AddressOrigin.DHCP")
                    {
                        ipaddress =
                            std::get<std::string>(properties["Address"]);
                        ipv6AddressSource = 0x81; // Looking at bit 0 and bit 7
                        prefixLength =
                            std::get<uint8_t>(properties["PrefixLength"]);
                        status = 0;
                    }
                    else
                    {
                        status = 1;
                    }
                }
                // ignore the exception, as it is a valid condition that
                // the system is not configured with any IP.
                catch (InternalFailure& e)
                {
                    // nothing to do.
                }
            }
            else if (channelConf->lan_set_in_progress == SET_IN_PROGRESS)
            {
                ipaddress = channelConf->ipv6Addr;
                ipv6AddressSource = channelConf->ipv6AddressSource;
                prefixLength = channelConf->ipv6Prefix;
                status = channelConf->ipv6AddressStatus;
            }

            uint8_t ipv6SetSelector = 0;
            std::array<uint8_t, 22> buf = {current_revision, ipv6SetSelector,
                                           ipv6AddressSource};
            inet_pton(AF_INET6, ipaddress.c_str(),
                      reinterpret_cast<void*>(&buf[3]));
            buf[20] = prefixLength;
            buf[21] = status;

            std::copy(buf.begin(), buf.end(), static_cast<uint8_t*>(response));
            *data_len = buf.size();
            break;
        }
        case LanParam::IPV6_DHCPV6_DYNAMIC_DUID_STOR_LEN:
        {
            uint8_t duidLength = 0;
            // Only 1 read-only 16-byte Block needed
            duidLength = 1;

            std::array<uint8_t, 2> buf = {current_revision, duidLength};
            std::copy(buf.begin(), buf.end(), static_cast<uint8_t*>(response));
            *data_len = buf.size();
            break;
        }
        case LanParam::IPV6_DHCPV6_DYNAMIC_DUIDS:
        {
            std::string macAddress;
            if (channelConf->lan_set_in_progress == SET_COMPLETE)
            {
                auto macObjectInfo =
                    ipmi::getDbusObject(bus, ipmi::network::MAC_INTERFACE,
                                        ipmi::network::ROOT, ethdevice);

                auto variant = ipmi::getDbusProperty(
                    bus, macObjectInfo.second, macObjectInfo.first,
                    ipmi::network::MAC_INTERFACE, "MACAddress");

                macAddress = std::get<std::string>(variant);
            }
            else if (channelConf->lan_set_in_progress == SET_IN_PROGRESS)
            {
                macAddress = channelConf->macAddress;
            }

            std::array<uint8_t,
                       ipmi::network::IPV6_DUID_SIZE + sizeof(current_revision)>
                buf;
            buf = {current_revision,
                   reqptr->parameter_set,
                   reqptr->parameter_block,
                   DUID_LEN,
                   0, // Filler byte
                   DUID_LL_TYPE,
                   0, // Filler byte
                   DUIC_ETH_HW_TYPE};

            sscanf(macAddress.c_str(), ipmi::network::MAC_ADDRESS_FORMAT,
                   (&buf[8]), (&buf[9]), (&buf[10]), (&buf[11]), (&buf[12]),
                   (&buf[13]));

            std::copy(buf.begin(), buf.end(), static_cast<uint8_t*>(response));
            *data_len = buf.size();
            break;
        }
        case LanParam::IPV6_ROUTER_ADDRESS_CONF_CTRL:
        {
            // Determine if automated router discovery occurs when static
            // addresses are used for the bmc

            auto ethIP = ethdevice + "/" + ipmi::network::IPV6_TYPE;
            std::string networkInterfacePath;
            uint8_t dynamicRA;
            if (channelConf->lan_set_in_progress == SET_COMPLETE)
            {

                try
                {
                    ipmi::ObjectTree ancestorMap;
                    // if the system is having ip object,then
                    // get the IP object.
                    auto ipObject =
                        ipmi::getDbusObject(bus, ipmi::network::IP_INTERFACE,
                                            ipmi::network::ROOT, ethIP);

                    // Get the parent interface of the IP object.
                    try
                    {
                        ipmi::InterfaceList interfaces;
                        interfaces.emplace_back(
                            ipmi::network::ETHERNET_INTERFACE);

                        ancestorMap = ipmi::getAllAncestors(
                            bus, ipObject.first, std::move(interfaces));
                    }
                    catch (InternalFailure& e)
                    {
                        // if unable to get the parent interface
                        // then commit the error and return.
                        log<level::ERR>(
                            "Unable to get the parent interface",
                            entry("PATH=%s", ipObject.first.c_str()),
                            entry("INTERFACE=%s",
                                  ipmi::network::ETHERNET_INTERFACE));
                        return IPMI_CC_UNSPECIFIED_ERROR;
                    }
                    // for an ip object there would be single parent
                    // interface.
                    networkInterfacePath = ancestorMap.begin()->first;
                }
                catch (InternalFailure& e)
                {
                    // if there is no ip configured on the system,then
                    // get the network interface object.
                    auto networkInterfaceObject = ipmi::getDbusObject(
                        bus, ipmi::network::ETHERNET_INTERFACE,
                        ipmi::network::ROOT, ethdevice);

                    networkInterfacePath = networkInterfaceObject.first;
                }

                auto variant = ipmi::getDbusProperty(
                    bus, ipmi::network::SERVICE, networkInterfacePath,
                    ipmi::network::ETHERNET_INTERFACE, "IPv6AcceptRA");
                dynamicRA = std::get<bool>(variant);
            }
            else
            {
                dynamicRA = channelConf->ipv6RouterAddressConfigControl;
            }

            std::array<uint8_t, 2> buf = {current_revision, dynamicRA};
            std::copy(buf.begin(), buf.end(), static_cast<uint8_t*>(response));
            *data_len = buf.size();
            break;
        }
        case LanParam::IPV6_STATIC_ROUTER_1_IP_ADDR:
        {
            std::array<uint8_t, ipmi::network::IPV6_ADDRESS_SIZE_BYTE +
                                    sizeof(current_revision)>
                buf = {current_revision};
            inet_pton(AF_INET6, channelConf->ipv6GatewayAddr.c_str(),
                      reinterpret_cast<void*>(&buf[1]));
            std::copy(buf.begin(), buf.end(), static_cast<uint8_t*>(response));
            *data_len = buf.size();
            break;
        }
        case LanParam::IPV6_STATIC_ROUTER_1_PREFIX_LEN:
        {
            std::array<uint8_t, 2> buf = {current_revision,
                                          channelConf->ipv6GatewayPrefixLength};
            std::copy(buf.begin(), buf.end(), static_cast<uint8_t*>(response));
            *data_len = buf.size();
            break;
        }
        case LanParam::IPV6_STATIC_ROUTER_1_PREFIX_VAL:
        {
            constexpr uint8_t setSelector = 0;
            std::array<uint8_t, sizeof(setSelector) +
                                    ipmi::network::IPV6_ADDRESS_SIZE_BYTE +
                                    sizeof(current_revision)>
                buf = {current_revision, setSelector};

            inet_pton(AF_INET6, channelConf->ipv6GatewayPrefixValue.c_str(),
                      reinterpret_cast<void*>(&buf[2]));

            std::copy(buf.begin(), buf.end(), static_cast<uint8_t*>(response));
            *data_len = buf.size();
            break;
        }
        case LanParam::IPV6_STATIC_ROUTER_2_IP_ADDR:
        {
            std::array<uint8_t, ipmi::network::IPV6_ADDRESS_SIZE_BYTE +
                                    sizeof(current_revision)>
                buf = {current_revision};
            inet_pton(AF_INET6, channelConf->ipv6BackupGatewayAddr.c_str(),
                      reinterpret_cast<void*>(&buf[1]));
            std::copy(buf.begin(), buf.end(), static_cast<uint8_t*>(response));
            *data_len = buf.size();
            break;
        }
        case LanParam::IPV6_STATIC_ROUTER_2_PREFIX_LEN:
        {
            std::array<uint8_t, 2> buf = {
                current_revision, channelConf->ipv6BackupGatewayPrefixLength};
            std::copy(buf.begin(), buf.end(), static_cast<uint8_t*>(response));
            *data_len = buf.size();
            break;
        }
        case LanParam::IPV6_STATIC_ROUTER_2_PREFIX_VAL:
        {

            constexpr uint8_t setSelector = 0;
            std::array<uint8_t, sizeof(setSelector) +
                                    ipmi::network::IPV6_ADDRESS_SIZE_BYTE +
                                    sizeof(current_revision)>
                buf = {current_revision, setSelector};
            inet_pton(AF_INET6,
                      channelConf->ipv6BackupGatewayPrefixValue.c_str(),
                      reinterpret_cast<void*>(&buf[2]));

            std::copy(buf.begin(), buf.end(), static_cast<uint8_t*>(response));
            *data_len = buf.size();
            break;
        }
        default:
            log<level::ERR>("Unsupported parameter",
                            entry("PARAMETER=0x%x", reqptr->parameter));
            rc = IPMI_CC_PARM_NOT_SUPPORTED;
    }

    return rc;
}

void applyChanges(int channel)
{
    std::string ipaddress;
    std::string gateway;
    uint8_t prefix{};
    uint32_t vlanID{};
    std::string networkInterfacePath;
    ipmi::DbusObjectInfo ipObject;
    ipmi::DbusObjectInfo systemObject;

    auto ethdevice = ipmi::getChannelName(channel);
    if (ethdevice.empty())
    {
        log<level::ERR>("Unable to get the interface name",
                        entry("CHANNEL=%d", channel));
        return;
    }
    auto ethIp = ethdevice + "/" + ipmi::network::IP_TYPE;
    auto channelConf = getChannelConfig(channel);

    try
    {
        sdbusplus::bus::bus bus(ipmid_get_sd_bus_connection());

        log<level::INFO>("Network data from Cache",
                         entry("PREFIX=%s", channelConf->netmask.c_str()),
                         entry("ADDRESS=%s", channelConf->ipaddr.c_str()),
                         entry("GATEWAY=%s", channelConf->gateway.c_str()),
                         entry("VLAN=%d", channelConf->vlanID),
                         entry("IPSRC=%d", channelConf->ipsrc));
        if (channelConf->vlanID != ipmi::network::VLAN_ID_MASK)
        {
            // get the first twelve bits which is vlan id
            // not interested in rest of the bits.
            channelConf->vlanID = le32toh(channelConf->vlanID);
            vlanID = channelConf->vlanID & ipmi::network::VLAN_ID_MASK;
        }

        // if the asked ip src is DHCP then not interested in
        // any given data except vlan.
        if (channelConf->ipsrc != ipmi::network::IPOrigin::DHCP)
        {
            // always get the system object
            systemObject =
                ipmi::getDbusObject(bus, ipmi::network::SYSTEMCONFIG_INTERFACE,
                                    ipmi::network::ROOT);

            // the below code is to determine the mode of the interface
            // as the handling is same, if the system is configured with
            // DHCP or user has given all the data.
            try
            {
                ipmi::ObjectTree ancestorMap;

                ipmi::InterfaceList interfaces{
                    ipmi::network::ETHERNET_INTERFACE};

                // if the system is having ip object,then
                // get the IP object.
                ipObject = ipmi::getIPObject(bus, ipmi::network::IP_INTERFACE,
                                             ipmi::network::ROOT, ethIp);

                // Get the parent interface of the IP object.
                try
                {
                    ancestorMap = ipmi::getAllAncestors(bus, ipObject.first,
                                                        std::move(interfaces));
                }
                catch (InternalFailure& e)
                {
                    // if unable to get the parent interface
                    // then commit the error and return.
                    log<level::ERR>("Unable to get the parent interface",
                                    entry("PATH=%s", ipObject.first.c_str()),
                                    entry("INTERFACE=%s",
                                          ipmi::network::ETHERNET_INTERFACE));
                    commit<InternalFailure>();
                    channelConf->clear();
                    return;
                }

                networkInterfacePath = ancestorMap.begin()->first;
            }
            catch (InternalFailure& e)
            {
                // TODO Currently IPMI supports single interface,need to handle
                // Multiple interface through
                // https://github.com/openbmc/openbmc/issues/2138

                // if there is no ip configured on the system,then
                // get the network interface object.
                auto networkInterfaceObject =
                    ipmi::getDbusObject(bus, ipmi::network::ETHERNET_INTERFACE,
                                        ipmi::network::ROOT, ethdevice);

                networkInterfacePath = std::move(networkInterfaceObject.first);
            }

            // get the configured mode on the system.
            auto enableDHCP = variant_ns::get<bool>(ipmi::getDbusProperty(
                bus, ipmi::network::SERVICE, networkInterfacePath,
                ipmi::network::ETHERNET_INTERFACE, "DHCPEnabled"));

            // if ip address source is not given then get the ip source mode
            // from the system so that it can be applied later.
            if (channelConf->ipsrc == ipmi::network::IPOrigin::UNSPECIFIED)
            {
                channelConf->ipsrc = (enableDHCP)
                                         ? ipmi::network::IPOrigin::DHCP
                                         : ipmi::network::IPOrigin::STATIC;
            }

            // check whether user has given all the data
            // or the configured system interface is dhcp enabled,
            // in both of the cases get the values from the cache.
            if ((!channelConf->ipaddr.empty() &&
                 !channelConf->netmask.empty() &&
                 !channelConf->gateway.empty()) ||
                (enableDHCP)) // configured system interface mode = DHCP
            {
                // convert mask into prefix
                ipaddress = channelConf->ipaddr;
                prefix = ipmi::network::toPrefix(AF_INET, channelConf->netmask);
                gateway = channelConf->gateway;
            }
            else // asked ip src = static and configured system src = static
                 // or partially given data.
            {
                // We have partial filled cache so get the remaining
                // info from the system.

                // Get the network data from the system as user has
                // not given all the data then use the data fetched from the
                // system but it is implementation dependent,IPMI spec doesn't
                // force it.

                // if system is not having any ip object don't throw error,
                try
                {
                    auto properties = ipmi::getAllDbusProperties(
                        bus, ipObject.second, ipObject.first,
                        ipmi::network::IP_INTERFACE);

                    ipaddress = channelConf->ipaddr.empty()
                                    ? variant_ns::get<std::string>(
                                          properties["Address"])
                                    : channelConf->ipaddr;

                    prefix = channelConf->netmask.empty()
                                 ? variant_ns::get<uint8_t>(
                                       properties["PrefixLength"])
                                 : ipmi::network::toPrefix(
                                       AF_INET, channelConf->netmask);
                }
                catch (InternalFailure& e)
                {
                    log<level::INFO>(
                        "Failed to get IP object which matches",
                        entry("INTERFACE=%s", ipmi::network::IP_INTERFACE),
                        entry("MATCH=%s", ethIp.c_str()));
                }

                auto systemProperties = ipmi::getAllDbusProperties(
                    bus, systemObject.second, systemObject.first,
                    ipmi::network::SYSTEMCONFIG_INTERFACE);

                gateway = channelConf->gateway.empty()
                              ? variant_ns::get<std::string>(
                                    systemProperties["DefaultGateway"])
                              : channelConf->gateway;
            }
        }

        // Currently network manager doesn't support purging of all the
        // ip addresses and the vlan interfaces from the parent interface,
        // TODO once the support is there, will make the change here.
        // https://github.com/openbmc/openbmc/issues/2141.

        // TODO Currently IPMI supports single interface,need to handle
        // Multiple interface through
        // https://github.com/openbmc/openbmc/issues/2138

        // instead of deleting all the vlan interfaces and
        // all the ipv4 address,we will call reset method.
        // delete all the vlan interfaces

        ipmi::deleteAllDbusObjects(bus, ipmi::network::ROOT,
                                   ipmi::network::VLAN_INTERFACE);

        // set the interface mode  to static
        auto networkInterfaceObject =
            ipmi::getDbusObject(bus, ipmi::network::ETHERNET_INTERFACE,
                                ipmi::network::ROOT, ethdevice);

        // setting the physical interface mode to static.
        ipmi::setDbusProperty(
            bus, ipmi::network::SERVICE, networkInterfaceObject.first,
            ipmi::network::ETHERNET_INTERFACE, "DHCPEnabled", false);

        networkInterfacePath = networkInterfaceObject.first;

        // delete all the ipv4 addresses
        ipmi::deleteAllDbusObjects(bus, ipmi::network::ROOT,
                                   ipmi::network::IP_INTERFACE, ethIp);

        if (vlanID)
        {
            ipmi::network::createVLAN(bus, ipmi::network::SERVICE,
                                      ipmi::network::ROOT, ethdevice, vlanID);

            auto networkInterfaceObject = ipmi::getDbusObject(
                bus, ipmi::network::VLAN_INTERFACE, ipmi::network::ROOT);

            networkInterfacePath = networkInterfaceObject.first;
        }

        if (channelConf->ipsrc == ipmi::network::IPOrigin::DHCP)
        {
            ipmi::setDbusProperty(
                bus, ipmi::network::SERVICE, networkInterfacePath,
                ipmi::network::ETHERNET_INTERFACE, "DHCPEnabled", true);
        }
        else
        {
            // change the mode to static
            ipmi::setDbusProperty(
                bus, ipmi::network::SERVICE, networkInterfacePath,
                ipmi::network::ETHERNET_INTERFACE, "DHCPEnabled", false);

            if (!ipaddress.empty())
            {
                ipmi::network::createIP(bus, ipmi::network::SERVICE,
                                        networkInterfacePath, ipv4Protocol,
                                        ipaddress, prefix);
            }

            if (!channelConf->ipv6Addr.empty() &&
                channelConf->ipv6AddressSource ==
                    0x80) // Check if IPv6 static addresses are enabled
            {
                ipmi::network::createIP(bus, ipmi::network::SERVICE,
                                        networkInterfacePath, ipv6Protocol,
                                        channelConf->ipv6Addr,
                                        channelConf->ipv6Prefix);
            }

            if (!gateway.empty())
            {
                ipmi::setDbusProperty(bus, systemObject.second,
                                      systemObject.first,
                                      ipmi::network::SYSTEMCONFIG_INTERFACE,
                                      "DefaultGateway", std::string(gateway));
            }
            else if (!channelConf->ipv6GatewayAddr.empty())
            {
                ipmi::setDbusProperty(
                    bus, systemObject.second, systemObject.first,
                    ipmi::network::SYSTEMCONFIG_INTERFACE, "DefaultGateway",
                    std::string(channelConf->ipv6GatewayAddr));
            }
        }
        // set IPAddress Enables
        ipmi::setDbusProperty(
            bus, ipmi::network::SERVICE, networkInterfaceObject.first,
            ipmi::network::ETHERNET_INTERFACE, "IPAddressEnables",
            ipAddressEnablesType[channelConf->ipv6AddressingEnables]);

        ipmi::setDbusProperty(
            bus, ipmi::network::SERVICE, networkInterfaceObject.first,
            ipmi::network::ETHERNET_INTERFACE, "IPv6AcceptRA",
            (bool)channelConf->ipv6RouterAddressConfigControl);
    }
    catch (sdbusplus::exception::exception& e)
    {
        log<level::ERR>(
            "Failed to set network data", entry("PREFIX=%d", prefix),
            entry("ADDRESS=%s", ipaddress.c_str()),
            entry("GATEWAY=%s", gateway.c_str()), entry("VLANID=%d", vlanID),
            entry("IPSRC=%d", channelConf->ipsrc));

        commit<InternalFailure>();
    }

    channelConf->clear();
}

void commitNetworkChanges()
{
    for (const auto& channel : channelConfig)
    {
        if (channel.second->flush)
        {
            applyChanges(channel.first);
        }
    }
}

void createNetworkTimer()
{
    if (!networkTimer)
    {
        std::function<void()> networkTimerCallback(
            std::bind(&commitNetworkChanges));

        networkTimer = std::make_unique<phosphor::Timer>(networkTimerCallback);
    }
}

static int setSOLParameter(std::string property, const ipmi::Value& value)
{
    auto dbus = getSdBus();

    static std::string solService{};
    if (solService.empty())
    {
        try
        {
            solService = ipmi::getService(*dbus, solInterface, solPath);
        }
        catch (const sdbusplus::exception::SdBusError& e)
        {
            solService.clear();
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Error: get SOL service failed");
            return -1;
        }
    }
    try
    {
        ipmi::setDbusProperty(*dbus, solService, solPath, solInterface,
                              property, value);
    }
    catch (sdbusplus::exception_t&)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error setting sol parameter");
        return -1;
    }

    return 0;
}

static int getSOLParameter(std::string property, ipmi::Value& value)
{
    auto dbus = getSdBus();

    static std::string solService{};
    if (solService.empty())
    {
        try
        {
            solService = ipmi::getService(*dbus, solInterface, solPath);
        }
        catch (const sdbusplus::exception::SdBusError& e)
        {
            solService.clear();
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Error: get SOL service failed");
            return -1;
        }
    }
    try
    {
        value = ipmi::getDbusProperty(*dbus, solService, solPath, solInterface,
                                      property);
    }
    catch (sdbusplus::exception_t&)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error getting sol parameter");
        return -1;
    }

    return 0;
}

void initializeSOLInProgress()
{
    if (setSOLParameter("Progress", static_cast<uint8_t>(0)) < 0)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error initialize sol progress");
    }
}

//    For getsetSOLConfParams, there are still three tings TODO:
//    1. session less channel number request has to return error.
//    2. convert 0xE channel number.
//    3. have unique object for every session based channel.
ipmi_ret_t getSOLConfParams(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                            ipmi_request_t request, ipmi_response_t response,
                            ipmi_data_len_t dataLen, ipmi_context_t context)
{
    auto reqData = reinterpret_cast<const GetSOLConfParamsRequest*>(request);
    std::vector<uint8_t> outPayload;

    if (*dataLen < sizeof(GetSOLConfParamsRequest) - 2)
    {
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    *dataLen = 0;

    outPayload.push_back(solParameterRevision);
    if (reqData->getParamRev)
    {
        std::copy(outPayload.begin(), outPayload.end(),
                  static_cast<uint8_t*>(response));
        *dataLen = outPayload.size();
        return IPMI_CC_OK;
    }

    ipmi::Value value;
    switch (static_cast<sol::Parameter>(reqData->paramSelector))
    {
        case sol::Parameter::progress:
        {
            if (getSOLParameter("Progress", value) < 0)
            {
                return IPMI_CC_UNSPECIFIED_ERROR;
            }
            outPayload.push_back(std::get<uint8_t>(value));
            break;
        }
        case sol::Parameter::enable:
        {
            if (getSOLParameter("Enable", value) < 0)
            {
                return IPMI_CC_UNSPECIFIED_ERROR;
            }
            outPayload.push_back(static_cast<uint8_t>(std::get<bool>(value)));
            break;
        }
        case sol::Parameter::authentication:
        {
            uint8_t authentication = 0;
            if (getSOLParameter("Privilege", value) < 0)
            {
                return IPMI_CC_UNSPECIFIED_ERROR;
            }
            authentication = (std::get<uint8_t>(value) & 0x0f);

            if (getSOLParameter("ForceAuthentication", value) < 0)
            {
                return IPMI_CC_UNSPECIFIED_ERROR;
            }
            authentication |=
                (static_cast<uint8_t>(std::get<bool>(value)) << 6);

            if (getSOLParameter("ForceEncryption", value) < 0)
            {
                return IPMI_CC_UNSPECIFIED_ERROR;
            }
            authentication |=
                (static_cast<uint8_t>(std::get<bool>(value)) << 7);
            outPayload.push_back(authentication);
            break;
        }
        case sol::Parameter::accumulate:
        {
            if (getSOLParameter("AccumulateIntervalMS", value) < 0)
            {
                return IPMI_CC_UNSPECIFIED_ERROR;
            }
            outPayload.push_back(std::get<uint8_t>(value));

            if (getSOLParameter("Threshold", value) < 0)
            {
                return IPMI_CC_UNSPECIFIED_ERROR;
            }
            outPayload.push_back(std::get<uint8_t>(value));
            break;
        }
        case sol::Parameter::retry:
        {
            if (getSOLParameter("RetryCount", value) < 0)
            {
                return IPMI_CC_UNSPECIFIED_ERROR;
            }
            outPayload.push_back(std::get<uint8_t>(value) & 0x03);

            if (getSOLParameter("RetryIntervalMS", value) < 0)
            {
                return IPMI_CC_UNSPECIFIED_ERROR;
            }
            outPayload.push_back(std::get<uint8_t>(value));
            break;
        }
        case sol::Parameter::port:
        {
            uint16_t port = htole16(ipmiStdPort);
            auto buffer = reinterpret_cast<const uint8_t*>(&port);
            std::copy(buffer, buffer + sizeof(port),
                      std::back_inserter(outPayload));
            break;
        }
        default:
            return IPMI_CC_PARM_NOT_SUPPORTED;
    }
    std::copy(outPayload.begin(), outPayload.end(),
              static_cast<uint8_t*>(response));
    *dataLen = outPayload.size();

    return IPMI_CC_OK;
}

ipmi_ret_t setSOLConfParams(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                            ipmi_request_t request, ipmi_response_t response,
                            ipmi_data_len_t dataLen, ipmi_context_t context)
{
    auto reqData = reinterpret_cast<const SetSOLConfParamsRequest*>(request);

    // Check request length first
    switch (static_cast<sol::Parameter>(reqData->paramSelector))
    {
        case sol::Parameter::progress:
        case sol::Parameter::enable:
        case sol::Parameter::authentication:
        {
            if (*dataLen != sizeof(SetSOLConfParamsRequest) - 1)
            {
                *dataLen = 0;
                return IPMI_CC_REQ_DATA_LEN_INVALID;
            }
            break;
        }
        case sol::Parameter::accumulate:
        case sol::Parameter::retry:
        {
            if (*dataLen != sizeof(SetSOLConfParamsRequest))
            {
                *dataLen = 0;
                return IPMI_CC_REQ_DATA_LEN_INVALID;
            }
            break;
        }
        default:
            break;
    }

    *dataLen = 0;

    switch (static_cast<sol::Parameter>(reqData->paramSelector))
    {
        case sol::Parameter::progress:
        {
            uint8_t progress = reqData->value & progressMask;
            ipmi::Value currentProgress = 0;
            if (getSOLParameter("Progress", currentProgress) < 0)
            {
                return IPMI_CC_UNSPECIFIED_ERROR;
            }

            if ((std::get<uint8_t>(currentProgress) == 1) && (progress == 1))
            {
                return IPMI_CC_SET_IN_PROGRESS_ACTIVE;
            }

            if (setSOLParameter("Progress", progress) < 0)
            {
                return IPMI_CC_UNSPECIFIED_ERROR;
            }
            break;
        }
        case sol::Parameter::enable:
        {
            bool enable = reqData->value & enableMask;
            if (setSOLParameter("Enable", enable) < 0)
            {
                return IPMI_CC_UNSPECIFIED_ERROR;
            }
            break;
        }
        case sol::Parameter::authentication:
        {
            // if encryption is used authentication must also be used.
            if (reqData->auth.encrypt && !reqData->auth.auth)
            {
                return IPMI_CC_SYSTEM_INFO_PARAMETER_SET_READ_ONLY;
            }
            else if (reqData->auth.privilege <
                         static_cast<uint8_t>(sol::Privilege::userPriv) ||
                     reqData->auth.privilege >
                         static_cast<uint8_t>(sol::Privilege::oemPriv))
            {
                return IPMI_CC_INVALID_FIELD_REQUEST;
            }

            if ((setSOLParameter("Privilege", reqData->auth.privilege) < 0) ||
                (setSOLParameter("ForceEncryption",
                                 static_cast<bool>(reqData->auth.encrypt)) <
                 0) ||
                (setSOLParameter("ForceAuthentication",
                                 static_cast<bool>(reqData->auth.auth)) < 0))
            {
                return IPMI_CC_UNSPECIFIED_ERROR;
            }

            break;
        }
        case sol::Parameter::accumulate:
        {
            if (reqData->acc.threshold == 0)
            {
                return IPMI_CC_INVALID_FIELD_REQUEST;
            }
            if (setSOLParameter("AccumulateIntervalMS", reqData->acc.interval) <
                0)
            {
                return IPMI_CC_UNSPECIFIED_ERROR;
            }
            if (setSOLParameter("Threshold", reqData->acc.threshold) < 0)
            {
                return IPMI_CC_UNSPECIFIED_ERROR;
            }
            break;
        }
        case sol::Parameter::retry:
        {
            if ((setSOLParameter("RetryCount", reqData->retry.count) < 0) ||
                (setSOLParameter("RetryIntervalMS", reqData->retry.interval) <
                 0))
            {
                return IPMI_CC_UNSPECIFIED_ERROR;
            }

            break;
        }
        case sol::Parameter::port:
        {
            return IPMI_CC_SYSTEM_INFO_PARAMETER_SET_READ_ONLY;
        }
        case sol::Parameter::nvbitrate:
        case sol::Parameter::vbitrate:
        case sol::Parameter::channel:
        default:
            return IPMI_CC_PARM_NOT_SUPPORTED;
    }

    return IPMI_CC_OK;
}

void register_netfn_transport_functions()
{
    // As this timer is only for transport handler
    // so creating it here.
    createNetworkTimer();
    // <Wildcard Command>
    ipmi_register_callback(NETFUN_TRANSPORT, IPMI_CMD_WILDCARD, NULL,
                           ipmi_transport_wildcard, PRIVILEGE_USER);

    // <Set LAN Configuration Parameters>
    ipmi_register_callback(NETFUN_TRANSPORT, IPMI_CMD_SET_LAN, NULL,
                           ipmi_transport_set_lan, PRIVILEGE_ADMIN);

    // <Get LAN Configuration Parameters>
    ipmi_register_callback(NETFUN_TRANSPORT, IPMI_CMD_GET_LAN, NULL,
                           ipmi_transport_get_lan, PRIVILEGE_OPERATOR);

    ipmi_register_callback(NETFUN_TRANSPORT, IPMI_CMD_SET_SOL_CONF_PARAMS, NULL,
                           setSOLConfParams, PRIVILEGE_ADMIN);

    ipmi_register_callback(NETFUN_TRANSPORT, IPMI_CMD_GET_SOL_CONF_PARAMS, NULL,
                           getSOLConfParams, PRIVILEGE_ADMIN);

    // Initialize dbus property progress to 0 every time sol manager restart.
    initializeSOLInProgress();

    return;
}
