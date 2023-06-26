from service_node import ServiceNode, ToR, TerminalServer, Pdu, FireWall
from argparse import ArgumentParser
from service_node import upload_results_to_S3, get_secret
import os
from pynautobot import api
from prettytable import PrettyTable

url = "https://sot.infra.drivenets.net"
AWS_ACCESS_SECRET = (os.getenv("AWS_ACCESS_SECRET"),)
AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY")


def add_nautobot_tag(nautobot_instance, device):
    add_tag = input(
        f"All checks are succesfull. Do you want to add a tag for {device.name} in Nautobot(Y/N):"
    ).upper()
    if add_tag == "Y":
        tag_list = device.tags
        if not tag_list:
            tag_list = []
        prod_tag = nautobot_instance.extras.tags.get(name="test-prod")
        tag_list.append(prod_tag)
        update = {"tags": tag_list}
        device.update(update)
        print(f"{device.name} updated with {prod_tag.name}")


def main():
    parser = ArgumentParser(description="Usage:")

    # script arguments
    parser.add_argument(
        "-a", "--host", type=str, required=True, help="Device IP address or Hostname"
    )
    args = parser.parse_args()
    tokens = get_secret(fw_name="fw00" + args.host.split(".")[1])
    if not tokens["NAUTOBOT_TOKEN"]:
        return print(
            "Device information could not collected. Checks will not be executed"
        )
    nautobot = api(url=url, token=os.getenv("NAUTOBOT_TOKEN"))
    service_node = nautobot.dcim.devices.get(name=args.host)
    if not service_node:
        return print("Nautobot does not have the record for the node name.")
    site = service_node.site.name
    devices = nautobot.dcim.devices.filter(site=site)

    for device in devices:
        if args.host == device.name:
            sn_ip = device.primary_ip.address[:-3]
            break

    if not tokens["username"] or not tokens["password"]:
        return print("Username or password is missing. Checks will not be executed")

    # servicenode=ServiceNode(node_ip='10.255.250.20',name="t")
    # # servicenode.validate_cl_version_nce_connectivity()
    # servicenode.validate_cluster_type()
    # servicenode.validate_software()
    # servicenode.validate_ncp_connectivity()
    # servicenode.validate_ncf_connectivity()
    # servicenode.validate_ncc_connectivity()
    # servicenode.validate_ncm_connectivity()
    # servicenode.validate_ncs_connectivity()
    # servicenode.validate_ncp_fabric_connections()
    # servicenode.validate_ncp_active_lanes()
    # servicenode.validate_control_connections()
    # servicenode.validate_mgm_ip()
    # servicenode.validate_nce_psus()
    # servicenode.check_control_links_from_shell()
    # servicenode.validate_ncp_fan()
    # servicenode.validate_ncc_fan()
    # servicenode.validate_ncm_fan()
    # servicenode.validate_ncf_fan()
    # servicenode.validate_ncp_temps()
    # servicenode.validate_cplds()
    # servicenode.validate_onie_version()
    # servicenode.validate_bios_version()
    # servicenode.validate_base_os()
    # servicenode.validate_hw_revision()
    # servicenode.validate_ncm_ncc_ipmi()
    # servicenode.validate_eth_controller()
    # servicenode.validate_number_of_vADI_routes()
    # servicenode.validate_vadi_bgp_nbrs()
    # servicenode.validate_default_route()
    # servicenode.validate_bundle_interface()
    # servicenode.debug_call()

    if not tokens["FW_TOKEN"] or not tokens["GITHUB_TOKEN"]:
        return print("Firewall checks will not be executed")
    for device in devices:
        if "fw00" in device.name:
            fw_ip = device.primary_ip.address[:-3]
            break
    table = PrettyTable(field_names=["time", "status", "message"])

    firewall = FireWall(fw_ip=fw_ip, name=device.name)
    table = firewall.validate_tunnels(table)
    table = firewall.validate_ha_peers(table)
    table = firewall.validate_ha_health(table)
    table = firewall.validate_bgp_sessions(table)
    table = firewall.validate_sim_card(table)
    table = firewall.validate_wwan_interface(table)
    table = firewall.validate_fw_policy(table)
    print(table.get_string())
    if not "FAILURE" in table.get_string():
        add_nautobot_tag(nautobot_instance=nautobot, device=device)

    for device in devices:
        if "tor00" in device.name:
            tor_ip = device.primary_ip.address[:-3]
            break

    table.clear_rows()
    topofrack = ToR(tor_ip=tor_ip, name=device.name)
    topofrack.collect_tor_chasis_info()
    table = topofrack.validate_lldp_info(table, site_id=site)
    table = topofrack.validate_lacp(table)
    table = topofrack.validate_alarms(table)
    table = topofrack.validate_chasis_env(table)
    table = topofrack.validate_virtaul_chasis(table)
    print(table.get_string())

    if not "FAILURE" in table.get_string():
        add_nautobot_tag(nautobot_instance=nautobot, device=device)

    for device in devices:
        if "ts00" in device.name:
            ts_ip = device.primary_ip.address[:-3]
            break

    table.clear_rows()
    terminal_server = TerminalServer(ts_ip=ts_ip, name=device.name)
    terminal_server.validate_port_mapping(
        table, site_id=site, terminal_server=f"ts00.{site}"
    )
    print(table.get_string())
    if not "FAILURE" in table.get_string():
        add_nautobot_tag(nautobot_instance=nautobot, device=device)

    pdus = []
    for device in devices:
        if "pdu" in device.name:
            pdus.append(device)

    for pdu in pdus:
        table.clear_rows()
        power_dist = Pdu(pdu_ip=pdu.primary_ip.address[:-3], name=pdu.name)
        power_dist.validate_outlet_mapping(site, pdu.name, table)
        print(table.get_string())
        if not "FAILURE" in table.get_string():
            add_nautobot_tag(nautobot_instance=nautobot, device=pdu)

    # result_files=[]
    # for r in os.listdir('/Users/muhammedsozer/Documents/AcceptanceAutomation/results/'):
    #     if 'result' in r:
    #         result_files.append(r)

    # for f in result_files:
    #     upload_results_to_S3(filename=f, bucket="msozer-log-bucket")


if __name__ == "__main__":
    main()
