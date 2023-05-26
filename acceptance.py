from service_node import ServiceNode,ToR,TerminalServer,Pdu,FireWall
from argparse import ArgumentParser
from service_node import upload_results_to_S3,get_secret
import os
from pynautobot import api

url = "https://sot.infra.drivenets.net"
AWS_ACCESS_SECRET=os.getenv('AWS_ACCESS_SECRET'),
AWS_ACCESS_KEY=os.getenv('AWS_ACCESS_KEY')

def main():
    parser = ArgumentParser(description='Usage:')

    # script arguments
    parser.add_argument('-a', '--host', type=str, required=True,
                        help="Device IP address or Hostname")
    args = parser.parse_args()
    # tokens=get_secret(fw_name='fw00'+args.host.split('.')[1])
    # if not tokens['NAUTOBOT_TOKEN']:
    #     return print('Device information could not collected. Checks will not be executed')
    # nautobot = api(url=url, token=os.getenv('NAUTOBOT_TOKEN'))
    # service_node= nautobot.dcim.devices.get(name=args.host)
    # if not service_node:
    #     return print("Nautobot does not have the record for the node name.")
    # site=service_node.site.name
    # devices= nautobot.dcim.devices.filter(site=site)

    # for device in devices:
    #     if args.host == device.name:
    #         sn_ip=device.primary_ip.address[:-3]
    #         break                                                                   
    
    # if not tokens['username'] or not tokens['password']:
    #     return print('Username or password is missing. Checks will not be executed')

    servicenode=ServiceNode(node_ip='10.255.250.20',name="t")
    # servicenode.validate_cl_version_nce_connectivity()
    servicenode.validate_cluster_type()
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

    # if not tokens['FW_TOKEN'] or not tokens['GITHUB_TOKEN']:     
    #     return print("Firewall checks will not be executed")
    # for device in devices:
    #     if 'fw00' in device.name:
    #         fw_ip=device.primary_ip.address[:-3]
    #         break

    # firewall=FireWall(fw_ip=fw_ip, name=device.name)
    # # firewall.validate_tunnels()
    # # firewall.validate_ha_peers()
    # # firewall.validate_ha_health()
    # # firewall.validate_bgp_sessions()
    # # firewall.validate_sim_card()
    # # firewall.validate_wwan_interface()
    # firewall.validate_fw_policy()

    # for device in devices:
    #     if 'tor00' in device.name:
    #         tor_ip=device.primary_ip.address[:-3]
    #         break
    

    # topofrack=ToR(tor_ip=tor_ip, name=device.name)
    # topofrack.collect_tor_chasis_info()
    # topofrack.validate_lldp_info(site_id=site)
    # topofrack.validate_lacp()
    # topofrack.validate_alarms()
    # topofrack.validate_chasis_env()
    # topofrack.validate_virtaul_chasis()

    # for device in devices:
    #     if 'ts00' in device.name:
    #         ts_ip=device.primary_ip.address[:-3]
    #         break

    # terminal_server=TerminalServer(ts_ip=ts_ip, name=device.name)
    # terminal_server.validate_port_mapping(site_id=site,terminal_server=f"ts00.{site}")

    # pdus=[]
    # for device in devices:
    #     if 'pdu' in device.name:
    #         pdus.append(device)
    
    # for pdu in pdus:
    #     power_dist=Pdu(pdu_ip=pdu.primary_ip.address[:-3],name=pdu.name)
    #     power_dist.validate_outlet_mapping(site_id=site,name=pdu.name)


    # result_files=[]
    # for r in os.listdir('/Users/muhammedsozer/Documents/AcceptanceAutomation/results/'):
    #     if 'result' in r:
    #         result_files.append(r)

    # for f in result_files:
    #     upload_results_to_S3(filename=f, bucket="msozer-log-bucket")


if __name__ == "__main__":

    main()
