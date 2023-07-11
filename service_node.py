import logging
from multiprocessing import AuthenticationError
import xmltodict
import time
import logging
import boto3
import os
import re
import requests
import paramiko
import copy
import json
from collections import OrderedDict
from rpc_filters import Filters
from netmiko import ConnectHandler
from ncclient import manager
from botocore.exceptions import ClientError
from ncclient.xml_ import to_ele
from requests.structures import CaseInsensitiveDict
from prettytable import PrettyTable

directory = "/Users/muhammedsozer/Documents/AcceptanceAutomation/logs"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    filename="/Users/muhammedsozer/Documents/AcceptanceAutomation/logs/run_logs.log",
)

filters = Filters()

tor_fw_port_mapping = {
    "ge-0/0/1": "fw00-",
    "ge-1/0/1": "fw00-",
    "ge-0/0/2": "fw01-",
    "ge-1/0/2": "fw01-",
}

expected_system_version: str = "[17.1.11.19]"
expected_cluster_type: str = "CL-32"
control_interfaces = [
    "ctrl-ncm-A0/16",
    "ctrl-ncm-A0/18",
    "ctrl-ncm-A0/24",
    "ctrl-ncm-A0/25",
    "ctrl-ncm-A0/44",
    "ctrl-ncm-A0/48",
    "ctrl-ncm-A0/49",
    "ctrl-ncm-A0/51",
    "ctrl-ncm-A0/52",
    "ctrl-ncm-B0/16",
    "ctrl-ncm-B0/18",
    "ctrl-ncm-B0/24",
    "ctrl-ncm-B0/25",
    "ctrl-ncm-B0/44",
    "ctrl-ncm-B0/48",
    "ctrl-ncm-B0/49",
    "ctrl-ncm-B0/51",
    "ctrl-ncm-B0/52",
]
expected_onie_version = "2021.08_DN_2021.11.0v10"
expected_ncp_ncf_bios_version = "T99O114T12_R04.16"
expected_bios_mode = "UEFI"
expected_ncm_bios_version = "v40.1.0.1"
expected_ncc_bios_version = "HPE U32 v2.58 (11/24/2021)"
expected_baseos_version = "DriveNets BaseOS 2.180111571004"
expected_ncp_hw_revision = "3, Build: 2"
expected_ncf_hw_revision = "3, Build: 1"
expected_ncm_ipmi_version = "0.55"
expected_ncc_ipmi_version = "iLO 5 v2.60"
expected_eth_controller_description = (
    "Mellanox Technologies MT27800 Family [ConnectX-5]"
)
expected_eth_controller_version = "16.31.1200 (HPE0000000009)"
v4_global_prefix_threshold = 800000
v6_global_prefix_threshold = 150000
number_of_expected_v4_bgp_nbr = 3
number_of_expected_v6_bgp_nbr = 3

AWS_ACCESS_KEY = os.environ.get("AWS_ACCESS_KEY")
AWS_ACCESS_SECRET = os.environ.get("AWS_ACCESS_SECRET")


def get_secret(fw_name):
    """
    The function `get_secret` retrieves secret values from AWS Secrets Manager and sets environment
    variables for specific tokens.

    :param fw_name: The `fw_name` parameter is a string that represents the name of the firewall for
    which you want to retrieve the token from the Secrets Manager
    :return: The function `get_secret` returns a dictionary `token_check` which contains information
    about the availability of various tokens in the Secrets Manager.
    """
    secret_name = "site_acceptance_secrets"
    region_name = "us-east-1"
    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name="secretsmanager",
        region_name=region_name,
        aws_secret_access_key=AWS_ACCESS_SECRET,
        aws_access_key_id=AWS_ACCESS_KEY,
    )
    try:
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
    except ClientError as e:
        # For a list of exceptions thrown, see
        # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
        raise e

    # Decrypts secret using the associated KMS key.
    secret = get_secret_value_response["SecretString"]
    token_check = {}
    if json.loads(secret).get("username"):
        os.environ["USERNAME"] = json.loads(secret).get("username")
        global username
        username = os.getenv("USERNAME")
        token_check["username"] = True
    else:
        print(f"Secret Manager does not have the information for username")
        token_check["username"] = False

    if json.loads(secret).get("password"):
        os.environ["PASSWORD"] = json.loads(secret).get("password")
        global password
        password = os.getenv("PASSWORD")
        token_check["password"] = True
    else:
        print(f"Secret Manager does not have the information for password")
        token_check["password"] = False

    if json.loads(secret).get("GITHUB_TOKEN"):
        os.environ["GITHUB_TOKEN"] = json.loads(secret).get("GITHUB_TOKEN")
        global GITHUB_TOKEN
        GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
        token_check["GITHUB_TOKEN"] = True
    else:
        print(
            "Secret Manager does not have the information for GITHUB TOKEN \
              to retrieve up-to-date Firewall policy"
        )
        token_check["GITHUB_TOKEN"] = False

    if json.loads(secret).get(fw_name):
        os.environ["FW_TOKEN"] = json.loads(secret).get(fw_name)
        global FW_TOKEN
        FW_TOKEN = os.getenv("FW_TOKEN")
        token_check["FW_TOKEN"] = True
    else:
        print(f"Secret Manager does not have the token for {fw_name}")
        token_check["FW_TOKEN"] = False

    if json.loads(secret).get("nautobot_token"):
        os.environ["NAUTOBOT_TOKEN"] = json.loads(secret).get("nautobot_token")
        global NAUTOBOT_TOKEN
        NAUTOBOT_TOKEN = os.getenv("NAUTOBOT_TOKEN")
        token_check["NAUTOBOT_TOKEN"] = True
    else:
        print(f"Secret Manager does not have the Nautobot Token")
        token_check["NAUTOBOT_TOKEN"] = False

    return token_check


# The `ServiceNode` class represents a service node with an IP address, a connection, an SSH
# connection, and a name.
class ServiceNode:
    def __init__(self, node_ip, name) -> None:
        self.node_ip = node_ip
        self.connection = self.__create_connection()
        self.ssh_connection = self.__ssh_connection()
        self.name = name

    def __create_connection(self):
        connection = manager.connect(
            host=self.node_ip,
            port=830,
            username="msozer",
            password="Rm.92522464",
            hostkey_verify=True,
            ssh_config=True,
        )
        return connection

    def __ssh_connection(self):
        net_connect = ConnectHandler(
            device_type="dnos",
            host=self.node_ip,
            username="msozer",
            password="Rm.92522464",
        )

        return net_connect

    def test_call(self):
        replay_xml = self.connection.dispatch(to_ele(filters.command_rpc)).xml

    def debug_call(self):
        rpc_reply = self.connection.get(("subtree", filters.filter_eth_controller))
        dicdata = xmltodict.parse(rpc_reply.xml)
        print(dicdata)

    def validate_cl_version_nce_connectivity(self):
        # uses SSH. will not be used in v18
        output = self.ssh_connection.send_command("show system")
        cluster_type = (
            re.findall(r"System Type:\sCL-\d*", output)[0].split(":")[1].strip()
        )
        system_version = re.findall(r"Version: DNOS\s\[.*\]", output)[0].split()[2]

        if expected_cluster_type == cluster_type:
            result = f"SUCCESS: Cluster type matched with expected type {cluster_type}"
        else:
            result = f"FAILURE: Cluster type({cluster_type}) does not matched with expected type which is {expected_cluster_type}"

        print(result)

        with open(f"results-{self.node_ip}.log", "a") as result_file:
            result_file.write(time.asctime() + " " + result + "\n")

        if expected_system_version == system_version:
            result = f"SUCCESS: System version matched with expected version {system_version}"
        else:
            result = f"FAILURE: System version({system_version}) does not matched with expected version which is {expected_system_version}"
        print(result)

        nce = {}
        for line in output.split("\n"):
            if "|" in line and "NC" in line:
                line = line.strip()
                line = line.strip("|")
                line = line.split("|")
                switch_type = line[0].strip()
                switch_id = line[1].strip()
                admin = line[2].strip()
                operational = line[3].strip()
                nce[f"{switch_type}-{switch_id}"] = {
                    "Admin": admin,
                    "Operational": operational,
                }

        for key, value in nce.items():
            if "up" in value["Operational"]:
                result = f"SUCCESS: {key} is {value['Operational']}"
            else:
                result = f"FAILURE: {key} is {value['Operational']}"
            print(result)
            with open("results.log", "a") as result_file:
                result_file.write(time.asctime() + " " + result + "\n")

    def validate_cluster_type(self, expected_cluster_type: str = expected_cluster_type):
        """
        The function `validate_cluster_type` checks if the cluster type obtained from an RPC reply matches
        the expected cluster type and logs the result.

        :param expected_cluster_type: The parameter `expected_cluster_type` is a string that represents the
        expected cluster type. It is used to compare with the actual cluster type obtained from the RPC
        reply
        :type expected_cluster_type: str
        :return: a string indicating the result of the cluster type validation.
        """
        rpc_reply = self.connection.get(("subtree", filters.filter_cluster_version))
        dicdata = xmltodict.parse(rpc_reply.xml)
        try:
            cluster_type = dicdata["nc:rpc-reply"]["data"]["dn-top:drivenets-top"][
                "dn-system:system"
            ]["oper-items"]["system-type"]
        except KeyError as key:
            result = f"RPC reply does not have the neccessary key: {key}."
            with open("results.log", "a") as result_file:
                result_file.write(time.asctime() + " " + result + "\n")
            return result

        if expected_cluster_type == cluster_type:
            result = f"SUCCESS: Cluster type matched with expected type {cluster_type}"
        else:
            result = f"FAILURE: Cluster type({cluster_type}) does not matched with expected type which is {expected_cluster_type}"

        print(result)

        with open(
            f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log"
        ) as result_file:
            result_file.write(time.asctime() + " " + result + "\n")

    def validate_software(self, expected_system_version: str = expected_system_version):
        """
        The function `validate_software` validates the system version of a software and logs the result.

        :param expected_system_version: The parameter `expected_system_version` is the version of the system
        that you expect to validate against. It is a string that represents the expected system version
        :type expected_system_version: str
        """
        rpc_reply = self.connection.get(("subtree", filters.filter_cluster_version))
        dicdata = xmltodict.parse(rpc_reply.xml)
        try:
            system_version = dicdata["nc:rpc-reply"]["data"]["dn-top:drivenets-top"][
                "dn-system:system"
            ]["oper-items"]["system-version"]
        except KeyError as key:
            result = f"RPC reply does not have the neccessary key: {key}."

        if expected_system_version == system_version:
            result = f"SUCCESS: System version matched with expected version {system_version}"
        else:
            result = f"FAILURE: System version({system_version}) does not matched with expected version which is {expected_system_version}"
        print(result)

        with open(
            f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
            "a",
        ) as result_file:
            result_file.write(time.asctime() + " " + result + "\n")

    def validate_ncp_connectivity(self):
        """
        The function `validate_ncp_connectivity` retrieves NCP connectivity information from an RPC reply,
        checks if each NCP is operational, and logs the results.
        """
        rpc_reply = self.connection.get(("subtree", filters.filter_ncp_connectivity))
        dicdata = xmltodict.parse(rpc_reply.xml)
        try:
            ncp_data = dicdata["nc:rpc-reply"]["data"]["dn-top:drivenets-top"][
                "dn-system:system"
            ]["dn-sys-ncp:ncps"]["ncp"]
        except KeyError as key:
            result = f"RPC reply does not have the neccessary key: {key}."
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")

        for n, ncp in enumerate(ncp_data):
            if ncp["oper-items"]["oper-status"] == "up":
                result = f"SUCCESS: NCP-{n} is operational UP"
            else:
                result = f"FAILURE: NCP-{n} is NOT operational UP"
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")

    def validate_ncf_connectivity(self):
        """
        The function `validate_ncf_connectivity` retrieves NCF connectivity data from an XML response,
        checks if each NCF is operational, and logs the results.
        """
        rpc_reply = self.connection.get(("subtree", filters.filter_ncf_connectivity))
        dicdata = xmltodict.parse(rpc_reply.xml)

        try:
            ncf_data = dicdata["nc:rpc-reply"]["data"]["dn-top:drivenets-top"][
                "dn-system:system"
            ]["dn-sys-ncf:ncfs"]["ncf"]
        except KeyError as key:
            result = f"RPC reply does not have the neccessary key: {key}."
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")

        for n, ncf in enumerate(ncf_data):
            if ncf["oper-items"]["oper-status"] == "up":
                result = f"SUCCESS: NCF-{n} is operational UP"
            else:
                result = f"FAILURE: NCF-{n} is NOT operational UP"
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")

    def validate_ncc_connectivity(self):
        """
        The function `validate_ncc_connectivity` retrieves NCC connectivity data from an RPC reply, parses
        it, and checks the operational status of each NCC, printing the results and writing them to a log
        file.
        """
        rpc_reply = self.connection.get(("subtree", filters.filter_ncc_connectivity))
        dicdata = xmltodict.parse(rpc_reply.xml)
        try:
            ncc_data = dicdata["nc:rpc-reply"]["data"]["dn-top:drivenets-top"][
                "dn-system:system"
            ]["dn-sys-ncc:nccs"]["ncc"]
        except KeyError as key:
            result = f"RPC reply does not have the neccessary key: {key}."
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")

        for n, ncc in enumerate(ncc_data):
            if ncc["oper-items"]["oper-status"] == "active-up" and n == 0:
                result = f"SUCCESS: NCC-{n} is operational UP"
            elif ncc["oper-items"]["oper-status"] == "standby-up" and n == 1:
                result = f"SUCCESS: NCC-{n} is in standby state and operational UP"
            else:
                result = f"FAILURE: NCC-{n} is NOT operational UP"
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")

    def validate_ncm_connectivity(self):
        """
        The function `validate_ncm_connectivity` retrieves NCM connectivity information from a network
        device and logs the operational status of each NCM.
        """
        rpc_reply = self.connection.get(("subtree", filters.filter_ncm_connectivity))
        dicdata = xmltodict.parse(rpc_reply.xml)
        try:
            ncm_data = dicdata["nc:rpc-reply"]["data"]["dn-top:drivenets-top"][
                "dn-system:system"
            ]["dn-sys-ncm:ncms"]["ncm"]
        except KeyError as key:
            result = f"RPC reply does not have the neccessary key:{key}."
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")

        for n, ncm in enumerate(ncm_data):
            if ncm["oper-items"]["oper-status"] == "up":
                result = f"SUCCESS: NCM-{n} is operational UP"
            else:
                result = f"FAILURE: NCM-{n} is NOT operational UP"
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")

    def validate_ncs_connectivity(self):
        """
        The function `validate_ncs_connectivity` checks the state and operational status of the NCS (Network
        Control System) and logs the result.
        """
        output = self.ssh_connection.send_command("show system")
        spltoutput = output.split("|")
        # TODO: add try except block for NCS index
        ncs_index = spltoutput.index(" NCS  ")
        is_enabled = spltoutput[ncs_index + 2]
        is_operational = spltoutput[ncs_index + 3]

        if is_enabled.strip() == "enabled" and is_operational.strip() == "up":
            result = "SUCCESS: NCS is ENABLED and operational UP"
        else:
            result = f"FAILURE: Please check NCS state is {is_enabled} and operational status is {is_operational}"
        print(result)
        with open(
            f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
            "a",
        ) as result_file:
            result_file.write(time.asctime() + " " + result + "\n")

    def validate_ncp_fabric_connections(self):
        """
        The function `validate_ncp_fabric_connections` retrieves data from an XML response, checks if the
        necessary keys are present, and then validates the number of fabric connections for each NCP.
        :return: The code is returning a string that indicates whether the validation was successful or not
        for each NCP (Network Control Processor) in the fabric connections.
        """
        rpc_reply = self.connection.get(
            ("subtree", filters.filter_ncp_fabric_connection)
        )
        dicdata = xmltodict.parse(rpc_reply.xml)
        try:
            ncp_data = dicdata["nc:rpc-reply"]["data"]["dn-top:drivenets-top"][
                "dn-system:system"
            ]["dn-sys-ncp:ncps"]["ncp"]
        except KeyError as key:
            result = f"RPC reply does not have the neccessary key: {key}."
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")

        for n, ncp in enumerate(ncp_data):
            try:
                number_of_connection = ncp["oper-items"][
                    "dn-sys-backplane:backplane-statistics"
                ]["current-connected-fabric-interfaces"]
            except KeyError as key:
                return f"RPC reply does not have the neccessary key: {key}."
            if number_of_connection == "12":
                result = f"SUCCESS: NCP-{n} has 12 fabric connections"
            else:
                result = f"FAILURE: NCP-{n} has {number_of_connection} which does not meet the expectation"

            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")
        # output=self.ssh_connection.send_command("show system backplane fabric")
        # fabric_connectivity=re.findall(r'NCP-\d:\s\d*\/\d*', output)

        # for ncp in fabric_connectivity:
        #     if ncp.split()[1]=="12/12":
        #         result=f'SUCCESS: {ncp.split()[0]} has 12 fabric connections'
        #     else:
        #         result=f'FAILURE: {ncp.split()[0]} has {ncp.split()[1].split("/")[0]}  which does not meet the expectation'
        #     print(result)
        #     with open('results.log', 'a') as result_file:
        #         result_file.write (time.asctime() + " " + result + '\n')

    def validate_ncp_active_lanes(self):
        """
        The function `validate_ncp_active_lanes` retrieves data from an XML response, checks for specific
        keys, and prints and logs the active lanes information for each neighbor node.
        """
        rpc_reply = self.connection.get(("subtree", filters.filter_ncp_active_lanes))
        dicdata = xmltodict.parse(rpc_reply.xml)
        try:
            ncp_data = dicdata["nc:rpc-reply"]["data"]["dn-top:drivenets-top"][
                "dn-system:system"
            ]["dn-sy s-ncp:ncps"]["ncp"]
        except KeyError as key:
            result = f"RPC reply does not have the neccessary key: {key}."
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")
        for n, ncp in enumerate(ncp_data):
            neighbor_connections = ncp["oper-items"][
                "dn-sys-backplane:backplane-reachability-statistics"
            ]["neighbor-node"]
            for neighbour in neighbor_connections:
                if neighbour["reachability-state"] == "reachable":
                    if (
                        neighbour["current-reachable-active-lanes"] == "48"
                        and "NCF" in neighbour["neighbor-node-name"]
                    ):
                        result = f'NCP-{n} has {neighbour["current-reachable-active-lanes"]} active lanes towards {neighbour["neighbor-node-name"]}'
                    elif (
                        neighbour["current-reachable-active-lanes"] == "96"
                        and "NCP" in neighbour["neighbor-node-name"]
                    ):
                        result = f'NCP-{n} has {neighbour["current-reachable-active-lanes"]} active lanes towards {neighbour["neighbor-node-name"]}'
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")

        # output=self.ssh_connection.send_command("show system backplane control")
        # fabric_connectivity=re.findall(r'NCP-\d:\s\d*\/\d*', output)
        # parked

    def validate_control_connections(self):
        """
        The function `validate_control_connections` retrieves information about control connections from a
        network device and compares the expected and actual neighbor interfaces, logging the results.
        """
        interfaces = control_interfaces

        for interface in interfaces:
            rpc_reply = self.connection.get(
                (
                    "subtree",
                    filters.filter_backbone_control_connections(interface=interface),
                )
            )
            dicdata = xmltodict.parse(rpc_reply.xml)
            try:
                expected_nb_interface = dicdata["nc:rpc-reply"]["data"][
                    "dn-top:drivenets-top"
                ]["dn-interfaces:interfaces"]["interface"]["ncm-interfaces"][
                    "oper-items"
                ][
                    "expected-neighbor-interface"
                ][
                    "#text"
                ]
            except KeyError as key:
                result = f"RPC reply does not have the neccessary key: {key}."
                print(result)
                with open(
                    f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                    "a",
                ) as result_file:
                    result_file.write(time.asctime() + " " + result + "\n")

            try:
                actual_nb_interface = dicdata["nc:rpc-reply"]["data"][
                    "dn-top:drivenets-top"
                ]["dn-interfaces:interfaces"]["interface"]["ncm-interfaces"][
                    "oper-items"
                ][
                    "actual-neighbor-interface"
                ][
                    "#text"
                ]
            except KeyError as key:
                result = f"RPC reply does not have the neccessary key {key}."
                print(result)
                with open(
                    f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                    "a",
                ) as result_file:
                    result_file.write(time.asctime() + " " + result + "\n")

            if expected_nb_interface == actual_nb_interface:
                result = f"management connections are done as expected {interface} <<>> {actual_nb_interface}"
            else:
                result = f"expected neigbour interface for {interface} is {expected_nb_interface} but cabling done through {actual_nb_interface}"
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")

    def validate_mgm_ip(self):
        """
        The function `validate_mgm_ip` retrieves management route information from a network device and
        checks if the next hop is configured correctly.
        """
        rpc_reply = self.connection.get(("subtree", filters.filter_oob_mgmt))
        dicdata = xmltodict.parse(rpc_reply.xml)
        try:
            route_info = dicdata["nc:rpc-reply"]["data"]["dn-top:drivenets-top"][
                "dn-system:system"
            ]["dn-oob-mgmt-route:management-route"]["vrfs"]["vrf"]["static"]["ipv4"][
                "routes"
            ][
                "route"
            ]
        except KeyError as key:
            result = f"RPC reply does not have the neccessary key: {key}."
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")

        rpc_reply = self.connection.get(("subtree", filters.filter_system_name))
        dicdata = xmltodict.parse(rpc_reply.xml)
        sys_name = dicdata["nc:rpc-reply"]["data"]["dn-top:drivenets-top"][
            "dn-system:system"
        ]["config-items"]["name"]
        mgmt_subnet = filters.site_mgmt_ip[sys_name]
        next_hop = mgmt_subnet[:-5] + "1"
        for route in route_info:
            if route["prefix"] == "0.0.0.0/0":
                cf_route = route["config-items"]["next-hop"]
                if cf_route == next_hop:
                    result = (
                        f"Next hop configured as {next_hop} on SN which is expected"
                    )
                else:
                    result = f"Next hop configured as {cf_route} on SN. Expected nexthop is {next_hop}"
                print(result)
                with open(
                    f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                    "a",
                ) as result_file:
                    result_file.write(time.asctime() + " " + result + "\n")

    def validate_nce_psus(self):
        """
        The function `validate_nce_psus` retrieves information about power supply units (PSUs) from an XML
        response and checks their status, logging the results.
        """
        rpc_reply = self.connection.get(("subtree", filters.filter_all_psu))
        dicdata = xmltodict.parse(rpc_reply.xml)
        try:
            nccs_platform_info = dicdata["nc:rpc-reply"]["data"][
                "dn-top:drivenets-top"
            ]["dn-system:system"]["dn-sys-ncc:nccs"]["ncc"]
        except KeyError as key:
            result = f"RPC reply does not have the neccessary key: {key}."
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")
        try:
            ncps_platform_info = dicdata["nc:rpc-reply"]["data"][
                "dn-top:drivenets-top"
            ]["dn-system:system"]["dn-sys-ncp:ncps"]["ncp"]
        except KeyError as key:
            result = f"RPC reply does not have the neccessary key: {key}."
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")
        try:
            ncfs_platform_info = dicdata["nc:rpc-reply"]["data"][
                "dn-top:drivenets-top"
            ]["dn-system:system"]["dn-sys-ncf:ncfs"]["ncf"]
        except KeyError as key:
            result = f"RPC reply does not have the neccessary key: {key}."
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")

        for p, ncc in enumerate(nccs_platform_info):
            try:
                psus = ncc["config-items"]["dn-platform:platform"][
                    "power-supply-units"
                ]["oper-items"]["psu"]
            except KeyError as key:
                result = f"RPC reply does not have the neccessary key: {key}."
                print(result)
                with open(
                    f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                    "a",
                ) as result_file:
                    result_file.write(time.asctime() + " " + result + "\n")

            for n, psu in enumerate(psus):
                if psu["status"] == "OK":
                    result = f"PSU-{n} status is OK for NCC-{p}"
                else:
                    result = f"PSU-{n} status is FAIL for NCC-{p}"
                print(result)
                with open(
                    f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                    "a",
                ) as result_file:
                    result_file.write(time.asctime() + " " + result + "\n")

        for p, ncp in enumerate(ncps_platform_info):
            try:
                psus = ncc["config-items"]["dn-platform:platform"][
                    "power-supply-units"
                ]["oper-items"]["psu"]
            except KeyError as key:
                result = f"RPC reply does not have the neccessary key: {key}."
            for n, psu in enumerate(psus):
                if psu["status"] == "OK":
                    result = f"PSU-{n} status is OK for NCP-{p}"
                else:
                    result = f"PSU-{n} status is FAIL for NCP-{p}"

                print(result)
                with open(
                    f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                    "a",
                ) as result_file:
                    result_file.write(time.asctime() + " " + result + "\n")

        for p, ncf in enumerate(ncfs_platform_info):
            try:
                psus = ncc["config-items"]["dn-platform:platform"][
                    "power-supply-units"
                ]["oper-items"]["psu"]
            except KeyError as key:
                result = f"RPC reply does not have the neccessary key: {key}."
                print(result)
                with open(
                    f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                    "a",
                ) as result_file:
                    result_file.write(time.asctime() + " " + result + "\n")
            for n, psu in enumerate(psus):
                if psu["status"] == "OK":
                    result = f"PSU-{n} status is OK for NCF-{p}"
                else:
                    result = f"PSU-{n} status is FAIL for NCF-{p}"
                print(result)
                with open(
                    f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                    "a",
                ) as result_file:
                    result_file.write(time.asctime() + " " + result + "\n")

    def check_control_links_from_shell(self):
        """
        The function `check_control_links_from_shell` checks the state of various network interfaces and
        writes the results to a log file.
        """
        self.ssh_connection._enter_shell(ncc=0)
        self.ssh_connection.send_command("access_host.sh")
        output_ctrl_ncc0 = self.ssh_connection.send_command("ip -c a | grep ctrl")
        output_mgmt_ncc0 = self.ssh_connection.send_command("ip -c a | grep mgmt")
        self.ssh_connection.disconnect()
        new_connection = self.__ssh_connection()
        new_connection._enter_shell(ncc=1)
        new_connection.send_command("access_host.sh")
        output_ctrl_ncc1 = new_connection.send_command("ip -c a | grep ctrl")
        output_mgmt_ncc1 = new_connection.send_command("ip -c a | grep mgmt")
        new_connection.disconnect()
        output_ncc0_split = output_ctrl_ncc0.split(":")
        output_ncc1_split = output_ctrl_ncc1.split(":")
        interface_index_1_ncc0 = output_ncc0_split.index(" ens1f0np0")
        interface_index_2_ncc0 = output_ncc0_split.index(" ens2f0np0")
        interface_index_3_ncc0 = output_ncc0_split.index(" ctrl-bond")
        interface_index_1_ncc1 = output_ncc1_split.index(" ens1f0np0")
        interface_index_2_ncc1 = output_ncc1_split.index(" ens2f0np0")
        interface_index_3_ncc1 = output_ncc1_split.index(" ctrl-bond")
        check_pattern_if = "<BROADCAST,MULTICAST,SLAVE,UP,LOWER_UP>"
        check_pattern_bond = "<BROADCAST,MULTICAST,MASTER,UP,LOWER_UP>"
        result = {}
        if check_pattern_if in output_ncc0_split[interface_index_1_ncc0 + 1]:
            result = "NCC0 ens1f0np0 state is UP"
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")
        else:
            result = "NCC0 ens1f0np0 state is not in UP state. Please check the control conenections"
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")

        if check_pattern_if in output_ncc0_split[interface_index_2_ncc0 + 1]:
            result = "NCC0 ens2f0np0 state is UP"
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")
        else:
            result = "NCC0 ens2f0np0 state is not in UP state. Please check the control conenections"
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")

        if check_pattern_bond in output_ncc0_split[interface_index_3_ncc0 + 1]:
            result = "NCC0 ctrl-bond state is UP"
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")
        else:
            result = "NCC0 ctrl-bond state is not in UP state. Please check the control conenections"
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")

        if check_pattern_if in output_ncc1_split[interface_index_1_ncc1 + 1]:
            result = "NCC1 ens1f0np0 state is UP"
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")
        else:
            result = "NCC1 ens1f0np0 state is not in UP state. Please check the control conenections"
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")

        if check_pattern_if in output_ncc1_split[interface_index_2_ncc1 + 1]:
            result = "NCC1 ens2f0np0 state is UP"
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")
        else:
            result = "NCC1 ens2f0np0 state is not in UP state. Please check the control conenections"
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")

        if check_pattern_bond in output_ncc1_split[interface_index_3_ncc1 + 1]:
            result = "NCC1 ctrl-bond state is UP"
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")
        else:
            result = "NCC1 ctrl-bond state is not in UP state. Please check the control conenections"
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")

    def validate_ncp_fan(self):
        rpc_reply = self.connection.get(("subtree", filters.filter_ncp_fan))
        dicdata = xmltodict.parse(rpc_reply.xml)
        try:
            ncp_fan_data = dicdata["nc:rpc-reply"]["data"]["dn-top:drivenets-top"][
                "dn-system:system"
            ]["dn-sys-ncp:ncps"]["ncp"]
        except KeyError as key:
            result = f"RPC reply does not have the neccessary key: {key}."
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")

        for ncp in ncp_fan_data:
            try:
                fans = ncp["config-items"]["dn-platform:platform"]["fans"][
                    "oper-items"
                ]["fan"]
            except KeyError as key:
                result = f"RPC reply does not have the neccessary key: {key}."
                print(result)
                with open(
                    f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                    "a",
                ) as result_file:
                    result_file.write(time.asctime() + " " + result + "\n")
            for fan in fans:
                if fan["status"] == "OK" and fan["present"] == "YES":
                    result = f'NCP-{ncp["ncp-id"]} {fan["fan-id"]} status is OK'
                elif fan["status"] == "FAIL" and fan["present"] == "YES":
                    result = f'NCP-{ncp["ncp-id"]} {fan["fan-id"]} status is FAILED'
                else:
                    result = f'NCP-{ncp["ncp-id"]} {fan["fan-id"]} is not PRESENT'
                print(result)
                with open(
                    f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                    "a",
                ) as result_file:
                    result_file.write(time.asctime() + " " + result + "\n")

    def validate_ncc_fan(self):
        rpc_reply = self.connection.get(("subtree", filters.filter_ncc_fan))
        dicdata = xmltodict.parse(rpc_reply.xml)
        try:
            ncc_fan_data = dicdata["nc:rpc-reply"]["data"]["dn-top:drivenets-top"][
                "dn-system:system"
            ]["dn-sys-ncc:nccs"]["ncc"]
        except KeyError as key:
            result = f"RPC reply does not have the neccessary key: {key}."
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")

        for ncc in ncc_fan_data:
            try:
                fans = ncc["config-items"]["dn-platform:platform"]["fans"][
                    "oper-items"
                ]["fan"]
            except KeyError as key:
                result = f"RPC reply does not have the neccessary key: {key}."
                print(result)
                with open(
                    f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                    "a",
                ) as result_file:
                    result_file.write(time.asctime() + " " + result + "\n")
            for fan in fans:
                if fan["status"] == "OK" and fan["present"] == "YES":
                    result = f'NCC-{ncc["ncc-id"]} {fan["fan-id"]} status is OK'
                elif fan["status"] == "FAIL" and fan["present"] == "YES":
                    result = f'NCC-{ncc["ncc-id"]} {fan["fan-id"]} status is FAILED'
                else:
                    result = f'NCC-{ncc["ncc-id"]} {fan["fan-id"]} is not PRESENT'
                print(result)
                with open(
                    f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                    "a",
                ) as result_file:
                    result_file.write(time.asctime() + " " + result + "\n")

    def validate_ncf_fan(self):
        rpc_reply = self.connection.get(("subtree", filters.filter_ncf_fan))
        dicdata = xmltodict.parse(rpc_reply.xml)
        try:
            ncf_fan_data = dicdata["nc:rpc-reply"]["data"]["dn-top:drivenets-top"][
                "dn-system:system"
            ]["dn-sys-ncf:ncfs"]["ncf"]
        except KeyError as key:
            result = f"RPC reply does not have the neccessary key: {key}."
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")

        for ncf in ncf_fan_data:
            try:
                fans = ncf["config-items"]["dn-platform:platform"]["fans"][
                    "oper-items"
                ]["fan"]
            except KeyError as key:
                result = f"RPC reply does not have the neccessary key: {key}."
                print(result)
                with open(
                    f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                    "a",
                ) as result_file:
                    result_file.write(time.asctime() + " " + result + "\n")
            for fan in fans:
                if fan["status"] == "OK" and fan["present"] == "YES":
                    result = f'NCF-{ncf["ncf-id"]} {fan["fan-id"]} status is OK'
                elif fan["status"] == "FAIL" and fan["present"] == "YES":
                    result = f'NCF-{ncf["ncf-id"]} {fan["fan-id"]} status is FAILED'
                else:
                    result = f'NCF-{ncf["ncf-id"]} {fan["fan-id"]} is not PRESENT'
                print(result)
                with open(
                    f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                    "a",
                ) as result_file:
                    result_file.write(time.asctime() + " " + result + "\n")

    def validate_ncm_fan(self):
        rpc_reply = self.connection.get(("subtree", filters.filter_ncm_fan))
        dicdata = xmltodict.parse(rpc_reply.xml)
        try:
            ncm_fan_data = dicdata["nc:rpc-reply"]["data"]["dn-top:drivenets-top"][
                "dn-system:system"
            ]["dn-sys-ncm:ncms"]["ncm"]
        except KeyError as key:
            result = f"RPC reply does not have the neccessary key: {key}."
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")

        for ncm in ncm_fan_data:
            try:
                fans = ncm["config-items"]["dn-platform:platform"]["fans"][
                    "oper-items"
                ]["fan"]
            except KeyError as key:
                result = f"RPC reply does not have the neccessary key: {key}."
                print(result)
                with open(
                    f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                    "a",
                ) as result_file:
                    result_file.write(time.asctime() + " " + result + "\n")
            for fan in fans:
                if fan["status"] == "OK" and fan["present"] == "YES":
                    result = f'NCM-{ncm["ncm-id"]} {fan["fan-id"]} status is OK'
                elif fan["status"] == "FAIL" and fan["present"] == "YES":
                    result = f'NCM-{ncm["ncm-id"]} {fan["fan-id"]} status is FAILED'
                else:
                    result = f'NCM-{ncm["ncm-id"]} {fan["fan-id"]} is not PRESENT'
                print(result)
                with open(
                    f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                    "a",
                ) as result_file:
                    result_file.write(time.asctime() + " " + result + "\n")

    def validate_ncp_temps(self):
        rpc_reply = self.connection.get(("subtree", filters.filter_hw_temp))
        dicdata = xmltodict.parse(rpc_reply.xml)
        try:
            ncp_temps = dicdata["nc:rpc-reply"]["data"]["dn-top:drivenets-top"][
                "dn-system:system"
            ]["dn-sys-ncp:ncps"]["ncp"]
        except KeyError as key:
            result = f"RPC reply does not have the neccessary key: {key}."

        for ncp in ncp_temps:
            for status in ncp["config-items"]["dn-platform:platform"][
                "temperature-sensors"
            ]["oper-items"]["temperature-sensor"]:
                if status["status"] == "OK":
                    result = f'Sensor {status["sensor-name"]} status is OK'
                else:
                    result = f'Sensor {status["sensor-name"]} needs to be checked'
                print(result)
                with open(
                    f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                    "a",
                ) as result_file:
                    result_file.write(time.asctime() + " " + result + "\n")

    def validate_cplds(self):
        rpc_reply = self.connection.get(("subtree", filters.filter_ncp_ncf_ncm_cpld))
        dicdata = xmltodict.parse(rpc_reply.xml)
        try:
            ncps_cpld = dicdata["nc:rpc-reply"]["data"]["dn-top:drivenets-top"][
                "dn-system:system"
            ]["dn-sys-ncp:ncps"]["ncp"]
        except KeyError as key:
            result = f"RPC reply does not have the neccessary key: {key}."
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")
        try:
            ncfs_cpld = dicdata["nc:rpc-reply"]["data"]["dn-top:drivenets-top"][
                "dn-system:system"
            ]["dn-sys-ncf:ncfs"]["ncf"]
        except KeyError:
            result = f"RPC reply does not have the neccessary key: {key}."
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")
        try:
            ncms_cpld = dicdata["nc:rpc-reply"]["data"]["dn-top:drivenets-top"][
                "dn-system:system"
            ]["dn-sys-ncm:ncms"]["ncm"]
        except KeyError as key:
            result = f"RPC reply does not have the neccessary key: {key}."
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")

        for ncp in ncps_cpld:
            for cpu in ncp["config-items"]["dn-platform:platform"]["oper-items"][
                "cpld-version"
            ]:
                if cpu["cpld-id"] == "CPU CPLD":
                    if cpu["version"] == "0.30":
                        result = f'CPLD version of NCP-{ncp["ncp-id"]} is 0.30 which is expected'
                    else:
                        result = f'CPLD version of NCP-{ncp["ncp-id"]} is not 0.30. Please check the firmware version'
                print(result)
                with open(
                    f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                    "a",
                ) as result_file:
                    result_file.write(time.asctime() + " " + result + "\n")

        for ncf in ncfs_cpld:
            for cpu in ncf["config-items"]["dn-platform:platform"]["oper-items"][
                "cpld-version"
            ]:
                if cpu["cpld-id"] == "CPU CPLD":
                    if cpu["version"] == "0.30":
                        result = f'CPLD version of NCF-{ncf["ncf-id"]} is 0.30 which is expected'
                    else:
                        result = f'CPLD version of NCF-{ncf["ncf-id"]} is not 0.30. Please check the firmware version'
                print(result)
                with open(
                    f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                    "a",
                ) as result_file:
                    result_file.write(time.asctime() + " " + result + "\n")

        for ncm in ncms_cpld:
            try:
                elements = ncm["config-items"]["dn-platform:platform"]["oper-items"][
                    "cpld-version"
                ]
            except KeyError as key:
                result = f"RPC reply does not have the neccessary key: {key}."
                print(result)
                with open(
                    f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                    "a",
                ) as result_file:
                    result_file.write(time.asctime() + " " + result + "\n")
            for e in elements:
                if e["cpld-id"] == "1":
                    if e["version"] == "0xb":
                        result = f'CPLD version of NCM-{ncm["ncm-id"]} is 0xb which is expected'
                    else:
                        result = f'CPLD version of NCM-{ncm["ncm-id"]} is not 0xb. Please check the firmware version'
                    print(result)
                    with open(
                        f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                        "a",
                    ) as result_file:
                        result_file.write(time.asctime() + " " + result + "\n")

                if e["cpld-id"] == "2":
                    if e["version"] == "0x6":
                        result = f'CPLD version of NCM-{ncm["ncm-id"]} is 0x6 which is expected'
                    else:
                        result = f'CPLD version of NCM-{ncm["ncm-id"]} is not 0x6. Please check the firmware version'
                    print(result)
                    with open(
                        f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                        "a",
                    ) as result_file:
                        result_file.write(time.asctime() + " " + result + "\n")
                if e["cpld-id"] == "CPU":
                    if e["version"] == "0x1e":
                        result = f'CPLD version of NCM-{ncm["ncm-id"]} is 0x1e which is expected'
                    else:
                        result = f'CPLD version of NCM-{ncm["ncm-id"]} is not 0x1e. Please check the firmware version'
                    print(result)
                    with open(
                        f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                        "a",
                    ) as result_file:
                        result_file.write(time.asctime() + " " + result + "\n")
                if e["cpld-id"] == "FAN":
                    if e["version"] == "0x03":
                        result = f'CPLD version of NCM-{ncm["ncm-id"]} is 0x03 which is expected'
                    else:
                        result = f'CPLD version of NCM-{ncm["ncm-id"]} is not 0x03. Please check the firmware version'
                    print(result)
                    with open(
                        f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                        "a",
                    ) as result_file:
                        result_file.write(time.asctime() + " " + result + "\n")

    def validate_onie_version(self):
        rpc_reply = self.connection.get(("subtree", filters.filter_onie_version))
        dicdata = xmltodict.parse(rpc_reply.xml)
        try:
            ncps_onie = dicdata["nc:rpc-reply"]["data"]["dn-top:drivenets-top"][
                "dn-system:system"
            ]["dn-sys-ncp:ncps"]["ncp"]
        except KeyError as key:
            result = f"RPC reply does not have the neccessary key: {key}."
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")
        try:
            ncfs_onie = dicdata["nc:rpc-reply"]["data"]["dn-top:drivenets-top"][
                "dn-system:system"
            ]["dn-sys-ncf:ncfs"]["ncf"]
        except KeyError as key:
            result = f"RPC reply does not have the neccessary key: {key}."
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")
        try:
            ncms_onie = dicdata["nc:rpc-reply"]["data"]["dn-top:drivenets-top"][
                "dn-system:system"
            ]["dn-sys-ncm:ncms"]["ncm"]
        except KeyError as key:
            result = f"RPC reply does not have the neccessary key: {key}."
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")
        try:
            nccs_onie = dicdata["nc:rpc-reply"]["data"]["dn-top:drivenets-top"][
                "dn-system:system"
            ]["dn-sys-ncc:nccs"]["ncc"]
        except KeyError as key:
            result = f"RPC reply does not have the neccessary key: {key}."
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")

        for ncp in ncps_onie:
            try:
                onie_version = ncp["config-items"]["dn-platform:platform"][
                    "oper-items"
                ]["onie-version"]
            except KeyError as key:
                result = f"RPC reply does not have the neccessary key: {key}."
                print(result)
                with open(
                    f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                    "a",
                ) as result_file:
                    result_file.write(time.asctime() + " " + result + "\n")
            if onie_version == expected_onie_version:
                result = f'ONIE version of NCP-{ncp["ncp-id"]} is {onie_version} which is expected value'
            else:
                result = f'ONIE version of NCP-{ncp["ncp-id"]} is {onie_version}. Expected version is 2021.08_DN_2021.11.0v10'

            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")
        for ncf in ncfs_onie:
            try:
                onie_version = ncf["config-items"]["dn-platform:platform"][
                    "oper-items"
                ]["onie-version"]
            except KeyError as key:
                result = f"RPC reply does not have the neccessary key: {key}."
                print(result)
                with open(
                    f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                    "a",
                ) as result_file:
                    result_file.write(time.asctime() + " " + result + "\n")
            if onie_version == expected_onie_version:
                result = f'ONIE version of NCF-{ncf["ncf-id"]} is {onie_version} which is expected value'
            else:
                result = f'ONIE version of NCF-{ncf["ncf-id"]} is {onie_version}. Expected version is 2021.08_DN_2021.11.0v10'

            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")
        for ncm in ncms_onie:
            try:
                onie_version = ncm["config-items"]["dn-platform:platform"][
                    "oper-items"
                ]["onie-version"]
            except KeyError as key:
                result = f"RPC reply does not have the neccessary key: {key}."
            if onie_version == expected_onie_version:
                result = f'ONIE version of NCM-{ncm["ncm-id"]} is {onie_version} which is expected value'
            else:
                result = f'ONIE version of NCM-{ncm["ncm-id"]} is {onie_version}. Expected version is 2021.08_DN_2021.11.0v10'
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")
        for ncc in nccs_onie:
            try:
                onie_version = ncc["config-items"]["dn-platform:platform"][
                    "oper-items"
                ]["onie-version"]
            except KeyError as key:
                result = f"RPC reply does not have the neccessary key: {key}."
                print(result)
                with open(
                    f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                    "a",
                ) as result_file:
                    result_file.write(time.asctime() + " " + result + "\n")
            if onie_version == expected_onie_version:
                result = f'ONIE version of NCC-{ncc["ncc-id"]} is {onie_version} which is expected value'
            else:
                result = f'ONIE version of NCC-{ncc["ncc-id"]} is {onie_version}. Expected version is 2021.08_DN_2021.11.0v10'

            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")

    def validate_bios_version(self):
        rpc_reply = self.connection.get(("subtree", filters.filter_bios))
        dicdata = xmltodict.parse(rpc_reply.xml)
        try:
            ncps_bios = dicdata["nc:rpc-reply"]["data"]["dn-top:drivenets-top"][
                "dn-system:system"
            ]["dn-sys-ncp:ncps"]["ncp"]
        except KeyError as key:
            result = f"RPC reply does not have the neccessary key : {key}."
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")
        try:
            ncfs_bios = dicdata["nc:rpc-reply"]["data"]["dn-top:drivenets-top"][
                "dn-system:system"
            ]["dn-sys-ncf:ncfs"]["ncf"]
        except KeyError as key:
            result = f"RPC reply does not have the neccessary key : {key}."
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")
        try:
            ncms_bios = dicdata["nc:rpc-reply"]["data"]["dn-top:drivenets-top"][
                "dn-system:system"
            ]["dn-sys-ncm:ncms"]["ncm"]
        except KeyError as key:
            result = f"RPC reply does not have the neccessary key : {key}."
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")
        try:
            nccs_bios = dicdata["nc:rpc-reply"]["data"]["dn-top:drivenets-top"][
                "dn-system:system"
            ]["dn-sys-ncc:nccs"]["ncc"]
        except KeyError as key:
            result = f"RPC reply does not have the neccessary key : {key}."
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")

        for ncp in ncps_bios:
            try:
                bios_version = ncp["config-items"]["dn-platform:platform"][
                    "oper-items"
                ]["bios-version"]
            except KeyError as key:
                result = f"RPC reply does not have the neccessary key : {key}."
                print(result)
                with open(
                    f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                    "a",
                ) as result_file:
                    result_file.write(time.asctime() + " " + result + "\n")
            try:
                bios_mode = ncp["config-items"]["dn-platform:platform"]["oper-items"][
                    "bios-mode"
                ]
            except KeyError as key:
                result = f"RPC reply does not have the neccessary key : {key}."
                print(result)
                with open(
                    f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                    "a",
                ) as result_file:
                    result_file.write(time.asctime() + " " + result + "\n")
            if (
                bios_version == expected_ncp_ncf_bios_version
                and bios_mode == expected_bios_mode
            ):
                result = f'BIOS version of NCP-{ncp["ncp-id"]} is {bios_version} and BIOS mode is {bios_mode} which are expected values'
            elif (
                bios_version == expected_ncp_ncf_bios_version
                and not bios_mode == expected_bios_mode
            ):
                result = f'BIOS version of NCP-{ncp["ncp-id"]} is {bios_version} and but BIOS mode is {bios_mode}. Please check bios mode'
            elif (
                not bios_version == expected_ncp_ncf_bios_version
                and bios_mode == expected_bios_mode
            ):
                result = f'BIOS mode of NCP-{ncp["ncp-id"]}  is  {bios_mode} which is expected but BIOS version is {bios_version}. Please check bios version'
            else:
                resul = f'BIOS mode of NCP-{ncp["ncp-id"]}  is  {bios_mode} and BIOS version is {bios_version}. Please check bios version and mode'
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")

        for ncf in ncfs_bios:
            try:
                bios_version = ncf["config-items"]["dn-platform:platform"][
                    "oper-items"
                ]["bios-version"]
            except KeyError as key:
                result = f"RPC reply does not have the neccessary key : {key}."
                print(result)
                with open(
                    f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                    "a",
                ) as result_file:
                    result_file.write(time.asctime() + " " + result + "\n")
            try:
                bios_mode = ncf["config-items"]["dn-platform:platform"]["oper-items"][
                    "bios-mode"
                ]
            except KeyError as key:
                result = f"RPC reply does not have the neccessary key : {key}."
                print(result)
                with open(
                    f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                    "a",
                ) as result_file:
                    result_file.write(time.asctime() + " " + result + "\n")
            if (
                bios_version == expected_ncp_ncf_bios_version
                and bios_mode == expected_bios_mode
            ):
                result = f'BIOS version of NCF-{ncf["ncf-id"]} is {bios_version} and BIOS mode is {bios_mode} which are expected values'
            elif (
                bios_version == expected_ncp_ncf_bios_version
                and not bios_mode == expected_bios_mode
            ):
                result = f'BIOS version of NCF-{ncf["ncf-id"]} is {bios_version} and but BIOS mode is {bios_mode}. Please check bios mode'
            elif (
                not bios_version == expected_ncp_ncf_bios_version
                and bios_mode == expected_bios_mode
            ):
                result = f'BIOS mode of NCF-{ncf["ncf-id"]}  is  {bios_mode} which is expected but BIOS version is {bios_version}. Please check bios version'
            else:
                result = f'BIOS mode of NCF-{ncf["ncf-id"]}  is  {bios_mode} and BIOS version is {bios_version}. Please check bios version and mode'
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")

        for ncm in ncms_bios:
            try:
                bios_version = ncm["config-items"]["dn-platform:platform"][
                    "oper-items"
                ]["bios-version"]
            except KeyError as key:
                result = f"RPC reply does not have the neccessary key : {key}."
                print(result)
                with open(
                    f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                    "a",
                ) as result_file:
                    result_file.write(time.asctime() + " " + result + "\n")
            try:
                bios_mode = ncm["config-items"]["dn-platform:platform"]["oper-items"][
                    "bios-mode"
                ]
            except KeyError as key:
                result = f"RPC reply does not have the neccessary key : {key}."
                print(result)
                with open(
                    f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                    "a",
                ) as result_file:
                    result_file.write(time.asctime() + " " + result + "\n")
            if (
                bios_version == expected_ncm_bios_version
                and bios_mode == expected_bios_mode
            ):
                result = f'BIOS version of NCM-{ncm["ncm-id"]} is {bios_version} and BIOS mode is {bios_mode} which are expected values'
            elif (
                bios_version == expected_ncm_bios_version
                and not bios_mode == expected_bios_mode
            ):
                result = f'BIOS version of NCM-{ncm["ncm-id"]} is {bios_version} and but BIOS mode is {bios_mode}. Please check bios mode'
            elif (
                not bios_version == expected_ncm_bios_version
                and bios_mode == expected_bios_mode
            ):
                result = f'BIOS mode of NCM-{ncm["ncm-id"]}  is  {bios_mode} which is expected but BIOS version is {bios_version}. Please check bios version'
            else:
                result = f'BIOS mode of NCM-{ncm["ncm-id"]}  is  {bios_mode} and BIOS version is {bios_version}. Please check bios version and mode'
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")
        for ncc in nccs_bios:
            try:
                bios_version = ncc["config-items"]["dn-platform:platform"][
                    "oper-items"
                ]["bios-version"]
            except KeyError as key:
                result = f"RPC reply does not have the neccessary key : {key}."
                print(result)
                with open(
                    f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                    "a",
                ) as result_file:
                    result_file.write(time.asctime() + " " + result + "\n")
            try:
                bios_mode = ncc["config-items"]["dn-platform:platform"]["oper-items"][
                    "bios-mode"
                ]
            except KeyError as key:
                result = f"RPC reply does not have the neccessary key : {key}."
                print(result)
                with open(
                    f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                    "a",
                ) as result_file:
                    result_file.write(time.asctime() + " " + result + "\n")
            if (
                bios_version == expected_ncc_bios_version
                and bios_mode == expected_bios_mode
            ):
                result = f'BIOS version of NCC-{ncc["ncc-id"]} is {bios_version} and BIOS mode is {bios_mode} which are expected values'
            elif (
                bios_version == expected_ncc_bios_version
                and not bios_mode == expected_bios_mode
            ):
                result = f'BIOS version of NCC-{ncc["ncc-id"]} is {bios_version} and but BIOS mode is {bios_mode}. Please check bios mode'
            elif (
                not bios_version == expected_ncc_bios_version
                and bios_mode == expected_bios_mode
            ):
                result = f'BIOS mode of NCC-{ncc["ncc-id"]}  is  {bios_mode} which is expected but BIOS version is {bios_version}. Please check bios version'
            else:
                result = f'BIOS mode of NCC-{ncc["ncc-id"]}  is  {bios_mode} and BIOS version is {bios_version}. Please check bios version and mode'
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")

    def validate_base_os(self):
        rpc_reply = self.connection.get(("subtree", filters.filter_base_os))
        dicdata = xmltodict.parse(rpc_reply.xml)
        try:
            ncps_base_os = dicdata["nc:rpc-reply"]["data"]["dn-top:drivenets-top"][
                "dn-system:system"
            ]["dn-sys-ncp:ncps"]["ncp"]
        except KeyError as key:
            result = f"RPC reply does not have the neccessary key : {key}."
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")
        try:
            ncfs_base_os = dicdata["nc:rpc-reply"]["data"]["dn-top:drivenets-top"][
                "dn-system:system"
            ]["dn-sys-ncf:ncfs"]["ncf"]
        except KeyError as key:
            result = f"RPC reply does not have the neccessary key : {key}."
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")
        try:
            nccs_base_os = dicdata["nc:rpc-reply"]["data"]["dn-top:drivenets-top"][
                "dn-system:system"
            ]["dn-sys-ncc:nccs"]["ncc"]
        except KeyError as key:
            result = f"RPC reply does not have the neccessary key : {key}."
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")

        for ncp in ncps_base_os:
            try:
                baseos_version = ncp["config-items"]["dn-platform:platform"][
                    "oper-items"
                ]["host-os"]
            except KeyError as key:
                result = f"RPC reply does not have the neccessary key : {key}."
                print(result)
                with open(
                    f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                    "a",
                ) as result_file:
                    result_file.write(time.asctime() + " " + result + "\n")
            if baseos_version == expected_baseos_version:
                result = f'BaseOS version of NCP-{ncp["ncp-id"]} is {baseos_version} which is expected'
            else:
                result = f'BaseOS version of NCP-{ncp["ncp-id"]}  is {baseos_version}. Please check Base OS'
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")
        for ncf in ncfs_base_os:
            try:
                baseos_version = ncf["config-items"]["dn-platform:platform"][
                    "oper-items"
                ]["host-os"]
            except KeyError as key:
                result = f"RPC reply does not have the neccessary key : {key}."
            if baseos_version == expected_baseos_version:
                result = f'BaseOS version of NCF-{ncf["ncf-id"]} is {baseos_version} which is expected'
            else:
                result = f'BaseOS version of NCF-{ncf["ncf-id"]}  is {baseos_version}. Please check Base OS'

        for ncc in nccs_base_os:
            try:
                baseos_version = ncc["config-items"]["dn-platform:platform"][
                    "oper-items"
                ]["host-os"]
            except KeyError as key:
                result = f"RPC reply does not have the neccessary key : {key}."
            if baseos_version == expected_baseos_version:
                result = f'BaseOS version of NCC-{ncc["ncc-id"]} is {baseos_version} which is expected'
            else:
                result = f'BaseOS version of NCC-{ncc["ncc-id"]}  is {baseos_version}. Please check Base OS'

                print(result)
                with open(
                    f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                    "a",
                ) as result_file:
                    result_file.write(time.asctime() + " " + result + "\n")

    def validate_hw_revision(self):
        rpc_reply = self.connection.get(("subtree", filters.filter_hw_revision_ncp_ncf))
        dicdata = xmltodict.parse(rpc_reply.xml)
        try:
            ncps_hw_version = dicdata["nc:rpc-reply"]["data"]["dn-top:drivenets-top"][
                "dn-system:system"
            ]["dn-sys-ncp:ncps"]["ncp"]
        except KeyError as key:
            result = f"RPC reply does not have the neccessary key : {key}."
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")

        try:
            ncfs_hw_version = dicdata["nc:rpc-reply"]["data"]["dn-top:drivenets-top"][
                "dn-system:system"
            ]["dn-sys-ncf:ncfs"]["ncf"]
        except KeyError as key:
            result = f"RPC reply does not have the neccessary key : {key}."
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")

        for ncp in ncps_hw_version:
            try:
                hw_revision = ncp["config-items"]["dn-platform:platform"]["oper-items"][
                    "hardware-revision"
                ]
            except KeyError as key:
                result = f"RPC reply does not have the neccessary key : {key}."
                print(result)
                with open(
                    f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                    "a",
                ) as result_file:
                    result_file.write(time.asctime() + " " + result + "\n")

            if hw_revision == expected_ncp_hw_revision:
                result = f'HW revision of NCP-{ncp["ncp-id"]} is {hw_revision} which is expected'
            else:
                result = f'HW revision of NCP-{ncp["ncp-id"]}  is {hw_revision}. Please check HW Revision'
                print(result)
                with open(
                    f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                    "a",
                ) as result_file:
                    result_file.write(time.asctime() + " " + result + "\n")

        for ncf in ncfs_hw_version:
            try:
                hw_revision = ncf["config-items"]["dn-platform:platform"]["oper-items"][
                    "hardware-revision"
                ]
            except KeyError as key:
                result = f"RPC reply does not have the neccessary key : {key}."
                print(result)
                with open(
                    f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                    "a",
                ) as result_file:
                    result_file.write(time.asctime() + " " + result + "\n")

            if hw_revision == expected_ncf_hw_revision:
                result = f'HW revision of NCF-{ncf["ncf-id"]} is {hw_revision} which is expected'

            else:
                result = f'HW revision of NCF-{ncf["ncf-id"]}  is {hw_revision}. Please check HW Revision'
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")

    def validate_ncm_ncc_ipmi(self):
        rpc_reply = self.connection.get(("subtree", filters.filter_ncm_ncc_ipmi))
        dicdata = xmltodict.parse(rpc_reply.xml)
        try:
            ncm_ipmi = dicdata["nc:rpc-reply"]["data"]["dn-top:drivenets-top"][
                "dn-system:system"
            ]["dn-sys-ncm:ncms"]["ncm"]
        except KeyError as key:
            result = f"RPC reply does not have the neccessary key : {key}."
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")

        try:
            ncc_ipmi = dicdata["nc:rpc-reply"]["data"]["dn-top:drivenets-top"][
                "dn-system:system"
            ]["dn-sys-ncc:nccs"]["ncc"]
        except KeyError as key:
            result = f"RPC reply does not have the neccessary key : {key}."
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")

        for ncm in ncm_ipmi:
            try:
                ipmi_version = ncm["config-items"]["dn-platform:platform"][
                    "oper-items"
                ]["ipmi-version"]["image-1-version"]
            except KeyError as key:
                result = f"RPC reply does not have the neccessary key : {key}."
                print(result)
                with open(
                    f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                    "a",
                ) as result_file:
                    result_file.write(time.asctime() + " " + result + "\n")

            if ipmi_version == expected_ncm_ipmi_version:
                result = f'IPMI version of NCM-{ncm["ncm-id"]} is {ipmi_version} which is expected'
            else:
                result = f'IPMI version of NCM-{ncm["ncm-id"]}  is {ipmi_version}. Please check IPMI Version.'
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")

        for ncc in ncc_ipmi:
            try:
                ipmi_version = ncc["config-items"]["dn-platform:platform"][
                    "oper-items"
                ]["ipmi-version"]["image-1-version"]
            except KeyError as key:
                result = f"RPC reply does not have the neccessary key : {key}."
                print(result)
                with open(
                    f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                    "a",
                ) as result_file:
                    result_file.write(time.asctime() + " " + result + "\n")

            if ipmi_version == expected_ncc_ipmi_version:
                result = f'iLO version of NCC-{ncc["ncc-id"]} is {ipmi_version} which is expected'
            else:
                result = f'iLO version of NCC-{ncc["ncc-id"]}  is {ipmi_version}. Please check iLO Version.'

            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")

    def validate_eth_controller(self):
        rpc_reply = self.connection.get(("subtree", filters.filter_eth_controller))
        dicdata = xmltodict.parse(rpc_reply.xml)
        try:
            ncc_eth = dicdata["nc:rpc-reply"]["data"]["dn-top:drivenets-top"][
                "dn-system:system"
            ]["dn-sys-ncc:nccs"]["ncc"]
        except KeyError as key:
            result = f"RPC reply does not have the neccessary key : {key}."
            print(result)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + result + "\n")

        for ncc in ncc_eth:
            try:
                nics = ncc["config-items"]["dn-platform:platform"]["oper-items"][
                    "on-board-management-ethernet-controller-version"
                ]
            except KeyError as key:
                result = f"RPC reply does not have the neccessary key : {key}."
                print(result)
                with open(
                    f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                    "a",
                ) as result_file:
                    result_file.write(time.asctime() + " " + result + "\n")

            for nic in nics:
                description = nic["description"]
                version = nic["version"]
                if (
                    description == expected_eth_controller_description
                    and version == expected_eth_controller_version
                ):
                    result = f'Ethernet controller of NCC-{ncc["ncc-id"]} is {description} and version is {version} which are expected'
                elif (
                    description == expected_eth_controller_description
                    and not version == expected_eth_controller_version
                ):
                    result = f'Ethernet controller of NCC-{ncc["ncc-id"]} is {description} and but version is {version}. Please check controller version'
                else:
                    result = f'Ethernet controller of NCC-{ncc["ncc-id"]} is {description}. Please check controller'
                print(result)
                with open(
                    f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                    "a",
                ) as result_file:
                    result_file.write(time.asctime() + " " + result + "\n")

    def validate_number_of_vADI_routes(self):
        rpc_reply = self.connection.get(
            ("subtree", filters.filter_vrf_route_summary_vADI)
        )
        # return rpc_reply
        dicdata = xmltodict.parse(rpc_reply.xml)
        result = {}
        try:
            vrf_route_v4 = dicdata["nc:rpc-reply"]["data"]["dn-top:drivenets-top"][
                "dn-network-services:network-services"
            ]["dn-vrf:vrfs"]["vrf"]["oper-items"]["vrf-route-summary"][
                "ipv4-unicast-routes"
            ][
                "ebgp-routes"
            ]
            vrf_route_v6 = dicdata["nc:rpc-reply"]["data"]["dn-top:drivenets-top"][
                "dn-network-services:network-services"
            ]["dn-vrf:vrfs"]["vrf"]["oper-items"]["vrf-route-summary"][
                "ipv6-unicast-routes"
            ][
                "ebgp-routes"
            ]
        except KeyError as key:
            return f"RPC reply does not have the neccessary key : {key}."
        if int(vrf_route_v4) < v4_global_prefix_threshold:
            result["ipv4"] = {}
            result["ipv4"]["status"] = "FAILURE: "
            result["ipv4"][
                "message"
            ] = f"Number of the IPV4 prefixes is less than expected value. Number of Prefixes: {vrf_route_v4}, Global_prefixes_threshold:{v4_global_prefix_threshold}"
        else:
            result["ipv4"] = {}
            result["ipv4"]["status"] = "SUCCESS: "
            result["ipv4"][
                "message"
            ] = f"Number of the IPV4 prefixes is above the expected value. Number of Prefixes: {vrf_route_v4}, Global_prefixes_threshold:{v4_global_prefix_threshold}"
        if int(vrf_route_v6) < v6_global_prefix_threshold:
            result["ipv6"] = {}
            result["ipv6"]["status"] = "FAILURE: "
            result["ipv6"][
                "message"
            ] = f"Number of the IPV6 prefixes is less than expected value. Number of Prefixes: {vrf_route_v6}, Global_prefixes_threshold:{v6_global_prefix_threshold}"
        else:
            result["ipv6"] = {}
            result["ipv6"]["status"] = "SUCCESS: "
            result["ipv6"][
                "message"
            ] = f"Number of the IPV6 prefixes is above the expected value. Number of Prefixes: {vrf_route_v6}, Global_prefixes_threshold:{v6_global_prefix_threshold}"

        for key in result:
            output = result[key]["status"] + result[key]["message"]
            print(output)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + output + "\n")

    def validate_vadi_bgp_nbrs(self):
        rpc_reply = self.connection.get(
            ("subtree", filters.filter_number_of_bgp_nb_vADI)
        )
        dicdata = xmltodict.parse(rpc_reply.xml)
        result = {}
        try:
            nbrs = dicdata["nc:rpc-reply"]["data"]["dn-top:drivenets-top"][
                "dn-network-services:network-services"
            ]["dn-vrf:vrfs"]["vrf"]["protocols"]["dn-bgp:bgp"]["global"]["global-oper"][
                "bgp-summary"
            ][
                "global"
            ][
                "address-families"
            ][
                "address-family"
            ]
        except KeyError as key:
            return f"RPC reply does not have the neccessary key : {key}."
        for nbr in nbrs:
            if (
                nbr["address-family-type"] == "ipv4-unicast"
                and int(nbr["number-established-neighbors"])
                >= number_of_expected_v4_bgp_nbr
            ):
                result["v4"] = {}
                result["v4"]["status"] = "SUCCESS: "
                result["v4"][
                    "message"
                ] = f'Number of the v4 bgp nbrs meets the expectation. Number of BGP neigbors:{nbr["number-established-neighbors"]}'
                break
            else:
                result["v4"] = {}
                result["v4"]["status"] = "FAILURE: "
                result["v4"][
                    "message"
                ] = f'Number of the v4 bgp nbrs does not meet the expectation. Number of BGP neigbors:{nbr["number-established-neighbors"]}'

        for nbr in nbrs:
            if (
                nbr["address-family-type"] == "ipv6-unicast"
                and int(nbr["number-established-neighbors"])
                >= number_of_expected_v6_bgp_nbr
            ):
                result["v6"] = {}
                result["v6"]["status"] = "SUCCESS: "
                result["v6"][
                    "message"
                ] = f'Number of the v6 bgp nbrs meets the expectation. Number of BGP neigbors:{nbr["number-established-neighbors"]}'
                break
            else:
                result["v6"] = {}
                result["v6"]["status"] = "FAILURE: "
                result["v6"][
                    "message"
                ] = f'Number of the v6 bgp nbrs does not meet the expectation. Number of BGP neigbors:{nbr["number-established-neighbors"]}'

        for key in result:
            output = result[key]["status"] + result[key]["message"]
            print(output)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
                "a",
            ) as result_file:
                result_file.write(time.asctime() + " " + output + "\n")

    def validate_default_route(self):
        output = self.ssh_connection.send_command("show route vrf ISP_ADI 0.0.0.0/0")
        result = {}
        if "bgp" in output:
            result["status"] = "SUCCESS: "
            result["message"] = "Default route is in the VRF route table"
        else:
            result["status"] = "FAILURE: "
            result["message"] = "Default route is NOT in the VRF route table"
        output = result["status"] + result["message"]
        print(output)
        with open(
            f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
            "a",
        ) as result_file:
            result_file.write(time.asctime() + " " + output + "\n")

    def validate_bundle_interface(self):
        output = self.ssh_connection.send_command(
            "show interface bundle-60002 | tail 1"
        )
        result = {}
        interface = re.findall(r"ge100-[0,1]\/0\/\d*", output)
        if "ge100-0/0/2" in interface:
            if len(interface) == 1:
                if "up" in output:
                    result["status"] = "SUCCESS: "
                    result[
                        "message"
                    ] = "ge100-0/0/2 is the member of Bundle-60002 and state is up"
                else:
                    result["status"] = "FAILURE: "
                    result[
                        "message"
                    ] = "ge100-0/0/2 is the member of Bundle-60002 but state is DOWN"
            else:
                result["status"] = "FAILURE: "
                result[
                    "message"
                ] = "ge100-0/0/2 is the member of Bundle-60002 and but there is an unexpected member in bundle. Please check bundle configuration"
        else:
            result["status"] = "FAILURE: "
            result["message"] = "ge100-0/0/2 is NOT the member of Bundle-60002"

        output = result["status"] + result["message"]
        print(output)
        with open(
            f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.node_ip}-{self.name}.log",
            "a",
        ) as result_file:
            result_file.write(time.asctime() + " " + output + "\n")


class ToR:
    def __init__(self, tor_ip, name) -> None:
        self.tor_ip = tor_ip
        self.ssh_connection = self.__ssh_connection()
        self.name = name

    def __ssh_connection(self):
        net_connect = ConnectHandler(
            device_type="juniper",
            host=self.tor_ip,
            username=username,
            password=password,
        )

        return net_connect

    def collect_tor_chasis_info(self):
        output = self.ssh_connection.send_command("show chassis hardware | display xml")
        structured_output = xmltodict.parse(output)
        print(structured_output)

    def validate_lldp_info(
        self,
        table,
        site_id,
    ):
        output = self.ssh_connection.send_command("show lldp neighbors | display xml")
        structured_output = xmltodict.parse(output)
        lldp = structured_output["rpc-reply"]["lldp-neighbors-information"][
            "lldp-neighbor-information"
        ]
        result = {}
        for interface in lldp:
            if tor_fw_port_mapping.get(interface["lldp-local-port-id"]):
                result[interface["lldp-local-port-id"]] = {}
                if (
                    tor_fw_port_mapping[interface["lldp-local-port-id"]] + site_id
                    == interface["lldp-remote-system-name"]
                ):
                    result[interface["lldp-local-port-id"]]["status"] = "SUCCESS: "
                    result[interface["lldp-local-port-id"]]["message"] = (
                        f'Tor to FW connection for interface {interface["lldp-local-port-id"]} '
                        f'is to {interface["lldp-remote-system-name"]} as expeceted'
                    )
                    # output=result[interface['lldp-local-port-id']]['status']+ result[interface['lldp-local-port-id']]['message']
                    table.add_row(
                        [
                            time.asctime(),
                            result[interface["lldp-local-port-id"]]["status"],
                            result[interface["lldp-local-port-id"]]["message"],
                        ]
                    )
                    with open(
                        f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.tor_ip}-{self.name}.log",
                        "w",
                    ) as result_file:
                        result_file.write(table.get_string())
                else:
                    result[interface["lldp-local-port-id"]]["status"] = "FAILURE: "
                    result[interface["lldp-local-port-id"]]["message"] = (
                        f'Tor to FW connection for interface {interface["lldp-local-port-id"]} '
                        f'is to {interface["lldp-remote-system-name"]} which is not expeceted.'
                        "Please check the cabling between ToR and FW"
                    )
                    # output=result[interface['lldp-local-port-id']]['status']+ result[interface['lldp-local-port-id']]['message']
                    table.add_row(
                        [
                            time.asctime(),
                            result[interface["lldp-local-port-id"]]["status"],
                            result[interface["lldp-local-port-id"]]["message"],
                        ]
                    )
                    # print(output)
                    with open(
                        f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.tor_ip}-{self.name}.log",
                        "w",
                    ) as result_file:
                        result_file.write(table.get_string())
        for tor_interface in tor_fw_port_mapping:
            if not tor_interface in result:
                result[tor_interface] = {}
                result[tor_interface]["status"] = "FAILURE: "
                result[tor_interface][
                    "message"
                ] = f"{tor_interface} is not conneted to the FW. Please check cabling"
                # output=result[interface['lldp-local-port-id']]['status']+ result[interface['lldp-local-port-id']]['message']
                table.add_row(
                    [
                        time.asctime(),
                        result[interface["lldp-local-port-id"]]["status"],
                        result[interface["lldp-local-port-id"]]["message"],
                    ]
                )
                # print(output)
                with open(
                    f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.tor_ip}-{self.name}.log",
                    "w",
                ) as result_file:
                    result_file.write(table.get_string())

        if not result:
            result["ToR to FW connections"] = {}
            result["ToR to FW connections"]["status"] = "FAILURE: "
            result["ToR to FW connections"][
                "message"
            ] = f"Tor to FW is not completed on expected interfaces. Please check the cabling between ToR and FW"
            # output=result[interface['lldp-local-port-id']]['status']+ result[interface['lldp-local-port-id']]['message']
            table.add_row(
                [
                    time.asctime(),
                    result[interface["lldp-local-port-id"]]["status"],
                    result[interface["lldp-local-port-id"]]["message"],
                ]
            )
            # print(output)
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/site_acceptance/results-{self.tor_ip}-{self.name}.log",
                "w",
            ) as result_file:
                result_file.write(table.get_string())
        return table

    def validate_lacp(self, table):
        output = self.ssh_connection.send_command("show lacp interfaces | display xml")
        structured_output = xmltodict.parse(output)
        lacp = structured_output["rpc-reply"]["lacp-interface-information-list"][
            "lacp-interface-information"
        ]
        result = {}
        for l in lacp:
            if l["lag-lacp-header"].get("aggregate-name") == "ae0":
                result[l["lag-lacp-header"]["aggregate-name"]] = {}
                for interface in l["lag-lacp-protocol"]:
                    if interface["name"] in ["ge-0/0/1", "ge-1/0/1"]:
                        result[l["lag-lacp-header"]["aggregate-name"]][
                            interface["name"]
                        ] = {}
                        if interface["lacp-mux-state"] == "Collecting distributing":
                            result[l["lag-lacp-header"]["aggregate-name"]][
                                interface["name"]
                            ]["status"] = "SUCCESS: "
                            result[l["lag-lacp-header"]["aggregate-name"]][
                                interface["name"]
                            ]["message"] = (
                                f"Interface {interface['name']} is in {interface['lacp-mux-state']}"
                                f"and member of {l['lag-lacp-header']['aggregate-name']} "
                            )
                            # output=result[l['lag-lacp-header']['aggregate-name']][interface['name']]['status']+ \
                            #        result[l['lag-lacp-header']['aggregate-name']][interface['name']]['message']
                            table.add_row(
                                [
                                    time.asctime(),
                                    result[l["lag-lacp-header"]["aggregate-name"]][
                                        interface["name"]
                                    ]["status"],
                                    result[l["lag-lacp-header"]["aggregate-name"]][
                                        interface["name"]
                                    ]["message"],
                                ]
                            )
                            # print(output)
                            with open(
                                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.tor_ip}-{self.name}.log",
                                "w",
                            ) as result_file:
                                result_file.write(table.get_string())
                        else:
                            result[l["lag-lacp-header"]["aggregate-name"]][
                                interface["name"]
                            ]["status"] = "FAILURE: "
                            result[l["lag-lacp-header"]["aggregate-name"]][
                                interface["name"]
                            ]["message"] = (
                                f"Interface {interface['name']} is  member of {l['lag-lacp-header']['aggregate-name']}"
                                f"but it is in {interface['lacp-mux-state']} which is not expected"
                            )
                            # output=result[l['lag-lacp-header']['aggregate-name']][interface['name']]['status']+\
                            #        result[l['lag-lacp-header']['aggregate-name']][interface['name']]['message']
                            table.add_row(
                                time.asctime(),
                                result[l["lag-lacp-header"]["aggregate-name"]][
                                    interface["name"]
                                ]["status"],
                                result[l["lag-lacp-header"]["aggregate-name"]][
                                    interface["name"]
                                ]["message"],
                            )
                            # print(output)
                            with open(
                                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.tor_ip}-{self.name}.log",
                                "w",
                            ) as result_file:
                                result_file.write(table.get_string())
                    else:
                        result[l["lag-lacp-header"]["aggregate-name"]][
                            interface["name"]
                        ] = {}
                        result[l["lag-lacp-header"]["aggregate-name"]][
                            interface["name"]
                        ]["status"] = "FAILURE: "
                        result[l["lag-lacp-header"]["aggregate-name"]][
                            interface["name"]
                        ]["message"] = (
                            f"Interface {interface['name']} is  member of {l['lag-lacp-header']['aggregate-name']}"
                            " which is not one of the expected members"
                        )
                        # output=result[l['lag-lacp-header']['aggregate-name']][interface['name']]['status']+\
                        #        result[l['lag-lacp-header']['aggregate-name']][interface['name']]['message']
                        table.add_row(
                            time.asctime(),
                            result[l["lag-lacp-header"]["aggregate-name"]][
                                interface["name"]
                            ]["status"],
                            result[l["lag-lacp-header"]["aggregate-name"]][
                                interface["name"]
                            ]["message"],
                        )
                        # print(output)
                        with open(
                            f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.tor_ip}-{self.name}.log",
                            "w",
                        ) as result_file:
                            result_file.write(table.get_string())
            elif l["lag-lacp-header"].get("aggregate-name") == "ae1":
                result[l["lag-lacp-header"]["aggregate-name"]] = {}
                for interface in l["lag-lacp-protocol"]:
                    if interface["name"] in ["ge-0/0/2", "ge-1/0/2"]:
                        result[l["lag-lacp-header"]["aggregate-name"]][
                            interface["name"]
                        ] = {}
                        if interface["lacp-mux-state"] == "Collecting distributing":
                            result[l["lag-lacp-header"]["aggregate-name"]][
                                interface["name"]
                            ]["status"] = "SUCCESS: "
                            result[l["lag-lacp-header"]["aggregate-name"]][
                                interface["name"]
                            ]["message"] = (
                                f"Interface {interface['name']} is in {interface['lacp-mux-state']}"
                                f"and member of {l['lag-lacp-header']['aggregate-name']} "
                            )
                            # output=result[l['lag-lacp-header']['aggregate-name']][interface['name']]['status']+\
                            #        result[l['lag-lacp-header']['aggregate-name']][interface['name']]['message']
                            # print(output)
                            table.add_row(
                                [
                                    time.asctime(),
                                    result[l["lag-lacp-header"]["aggregate-name"]][
                                        interface["name"]
                                    ]["status"],
                                    result[l["lag-lacp-header"]["aggregate-name"]][
                                        interface["name"]
                                    ]["message"],
                                ]
                            )
                            with open(
                                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.tor_ip}-{self.name}.log",
                                "w",
                            ) as result_file:
                                result_file.write(table.get_string())
                        else:
                            result[l["lag-lacp-header"]["aggregate-name"]][
                                interface["name"]
                            ]["status"] = "FAILURE: "
                            result[l["lag-lacp-header"]["aggregate-name"]][
                                interface["name"]
                            ]["message"] = (
                                f"Interface {interface['name']} is  member of {l['lag-lacp-header']['aggregate-name']}"
                                f"but it is in {interface['lacp-mux-state']} which is not expected"
                            )
                            # output=result[l['lag-lacp-header']['aggregate-name']][interface['name']]['status']+\
                            #        result[l['lag-lacp-header']['aggregate-name']][interface['name']]['message']
                            # print(output)
                            table.add_row(
                                [
                                    time.asctime(),
                                    result[l["lag-lacp-header"]["aggregate-name"]][
                                        interface["name"]
                                    ]["status"],
                                    result[l["lag-lacp-header"]["aggregate-name"]][
                                        interface["name"]
                                    ]["message"],
                                ]
                            )
                            with open(
                                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.tor_ip}-{self.name}.log",
                                "w",
                            ) as result_file:
                                result_file.write(table.get_string())
                    else:
                        result[l["lag-lacp-header"]["aggregate-name"]][
                            interface["name"]
                        ] = {}
                        result[l["lag-lacp-header"]["aggregate-name"]][
                            interface["name"]
                        ]["status"] = "FAILURE: "
                        result[l["lag-lacp-header"]["aggregate-name"]][
                            interface["name"]
                        ][
                            "message"
                        ] = f"Interface {interface['name']} is  member of {l['lag-lacp-header']['aggregate-name']}"
                        # output=result[l['lag-lacp-header']['aggregate-name']][interface['name']]['status']+\
                        #        result[l['lag-lacp-header']['aggregate-name']][interface['name']]['message']
                        # print(output)
                        table.add_row(
                            [
                                time.asctime(),
                                result[l["lag-lacp-header"]["aggregate-name"]][
                                    interface["name"]
                                ]["status"],
                                result[l["lag-lacp-header"]["aggregate-name"]][
                                    interface["name"]
                                ]["message"],
                            ]
                        )
                        with open(
                            f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.tor_ip}-{self.name}.log",
                            "w",
                        ) as result_file:
                            result_file.write(table.get_string())

            else:
                result[l["lag-lacp-header"]["aggregate-name"]] = {}
                result[l["lag-lacp-header"]["aggregate-name"]]["status"] = "FAILURE: "
                result[l["lag-lacp-header"]["aggregate-name"]][
                    "message"
                ] = f"{l['lag-lacp-header']['aggregate-name']} is not an expected aggregation group"
                # output=result[l['lag-lacp-header']['aggregate-name']]['status']+\
                #        result[l['lag-lacp-header']['aggregate-name']]['message']
                # print(output)
                table.add_row(
                    [
                        time.asctime(),
                        result[l["lag-lacp-header"]["aggregate-name"]]["status"],
                        result[l["lag-lacp-header"]["aggregate-name"]]["message"],
                    ]
                )
                with open(
                    f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.tor_ip}-{self.name}.log",
                    "w",
                ) as result_file:
                    result_file.write(table.get_string())
        return table

    def validate_alarms(self, table):
        output = self.ssh_connection.send_command("show chassis alarms | display xml")
        structured_output = xmltodict.parse(output)
        result = {}
        alarm_list = []
        alarms = structured_output["rpc-reply"]["alarm-information"]
        if "no-active-alarms" in alarms["alarm-summary"].keys():
            result["status"] = "SUCCESS: "
            result["message"] = "There is no active alarm on the device"
            # output=result['status']+result['message']
            # print(output )
            table.add_row([time.asctime(), result["status"], result["message"]])
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.tor_ip}-{self.name}.log",
                "w",
            ) as result_file:
                result_file.write(table.get_string())
        else:
            for detail in alarms["alarm-detail"]:
                alarm_list.append(detail["alarm-description"])

            result["status"] = "FAILURE: "
            result["message"] = f"Please check alarms {alarm_list}"
            # output=result['status']+result['message']
            # print(output)
            table.add_row([[time.asctime(), result["status"], result["message"]]])
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.tor_ip}-{self.name}.log",
                "w",
            ) as result_file:
                result_file.write(table.get_string())
        return table

    def validate_chasis_env(self, table):
        output = self.ssh_connection.send_command(
            "show chassis environment | display xml"
        )
        structured_output = xmltodict.parse(output)
        items = structured_output["rpc-reply"]["environment-information"][
            "environment-item"
        ]
        result = {}
        for item in items:
            result[item["name"]] = {}
            if item["status"] == "OK":
                result[item["name"]]["status"] = "SUCCESS: "
                result[item["name"]]["message"] = f'{item["name"]} status is OK'
                # output=result[item['name']]['status']+result[item['name']]['message']
                # print(output)
                table.add_row(
                    [
                        time.asctime(),
                        result[item["name"]]["status"],
                        result[item["name"]]["message"],
                    ]
                )
                with open(
                    f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.tor_ip}-{self.name}.log",
                    "w",
                ) as result_file:
                    result_file.write(table.get_string())
            else:
                result[item["name"]]["status"] = "FAILURE: "
                result[item["name"]][
                    "message"
                ] = f'Plese check {item["name"]}. Status is {item["status"]}'
                # output=result[item['name']]['status']+result[item['name']]['message']
                # print(output )
                table.add_row(
                    [
                        time.asctime(),
                        result[item["name"]]["status"],
                        result[item["name"]]["message"],
                    ]
                )
                with open(
                    f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.tor_ip}-{self.name}.log",
                    "w",
                ) as result_file:
                    result_file.write(table.get_string())
        return table

    def validate_virtaul_chasis(self, table):
        output = self.ssh_connection.send_command(
            "show virtual-chassis status | display xml"
        )
        structured_output = xmltodict.parse(output)
        vc_info = structured_output["rpc-reply"]["virtual-chassis-information"][
            "preprovisioned-virtual-chassis-information"
        ]["virtual-chassis-mode"]
        number_of_members = len(
            structured_output["rpc-reply"]["virtual-chassis-information"][
                "member-list"
            ]["member"]
        )
        number_of_vcp_links = 0
        result = {}
        members = structured_output["rpc-reply"]["virtual-chassis-information"][
            "member-list"
        ]["member"]
        for member in members:
            for n in member["neighbor-list"]["neighbor"]:
                if n["neighbor-interface"]:
                    number_of_vcp_links += 1
        if vc_info == "Enabled":
            if number_of_members == 2:
                if number_of_vcp_links == 4:
                    result["status"] = "SUCCESS: "
                    result[
                        "message"
                    ] = "VC is enabled and has 2 members and total 4 vcp links"
                    # output=result['status']+result['message']
                    # print(output)
                    table.add_row([time.asctime(), result["status"], result["message"]])
                    with open(
                        f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.tor_ip}-{self.name}.log",
                        "w",
                    ) as result_file:
                        result_file.write(table.get_string())
                else:
                    result["status"] = "FAILURE: "
                    result[
                        "message"
                    ] = f"VC is enabled and but total number of vcp links is {number_of_vcp_links}"
                    # output=result['status']+result['message']
                    # print(output)
                    table.add_row([time.asctime(), result["status"], result["message"]])
                    with open(
                        f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results{self.tor_ip}-{self.name}.log",
                        "w",
                    ) as result_file:
                        result_file.write(table.get_string())
            else:
                result["status"] = "FAILURE: "
                result[
                    "message"
                ] = f"VC is enabled and but number of members is {number_of_members}"
                # output=result['status']+result['message']
                # print( output)
                table.add_row([time.asctime(), result["status"], result["message"]])
                with open(
                    f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results{self.tor_ip}-{self.name}.log",
                    "w",
                ) as result_file:
                    result_file.write(table.get_string())
        else:
            result["status"] = "FAILURE: "
            result["message"] = f"VC is not Enabled"
            # output=result['status']+result['message']
            # print(output)
            table.add_row([time.asctime(), result["status"], result["message"]])
            with open(
                f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results{self.tor_ip}-{self.name}.log",
                "w",
            ) as result_file:
                result_file.write(table.get_string())
        return table


class FireWall:
    def __init__(self, fw_ip, name) -> None:
        self.fw_ip = fw_ip
        self.name = name

    def ssh_connection(self, username, password):
        net_connect = ConnectHandler(
            device_type="fortinet",
            host=self.fw_ip,
            username=username,
            password=password,
        )

        return net_connect

    def validate_tunnels(self, table):
        url = f"https://{self.fw_ip}/api/v2/monitor/vpn/ipsec"
        payload = {}
        headers = {"Authorization": f"Bearer {FW_TOKEN}"}
        response_raw = requests.request(
            "GET", url, headers=headers, data=payload, verify=False
        )
        response = response_raw.json()["results"]
        expected_tunnel_names = [
            "TO-LTE",
            "AWS-TGW-T1",
            "AWS-TGW-T2",
            "AWS-TGW-T3",
            "AWS-TGW-T4",
        ]
        list_result = []
        tunnel_names = []
        for tunnel in response:
            result = {}
            result["name"] = tunnel["proxyid"][0]["p2name"]
            if tunnel["proxyid"][0]["status"] == "up":
                result["status"] = "SUCCESS: "
                result["message"] = f"Tunnel {tunnel['proxyid'][0]['p2name']} is UP"
            else:
                result["status"] = "FAILURE: "
                result["message"] = f"Tunnel {tunnel['proxyid'][0]['p2name']} is DOWN"
            list_result.append(result)
            tunnel_names.append(tunnel["proxyid"][0]["p2name"])

        missing_tunnel = [
            item for item in expected_tunnel_names if item not in tunnel_names
        ]

        if missing_tunnel:
            for tunnel in missing_tunnel:
                result = {}
                result["name"] = tunnel
                result["status"] = "FAILURE: "
                result[
                    "message"
                ] = f"Tunnel {tunnel} is missing. Please check the FW configurations"
                list_result.append(result)
        for result in list_result:
            # output=result["status"]+result["message"]
            # print(output)
            table.add_row([time.asctime(), result["status"], result["message"]])
        # print(table)
        # # print(table.get_string())
        with open(
            f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.fw_ip}-{self.name}.log",
            "w",
        ) as result_file:
            result_file.write(table.get_string())
        return table

    def validate_ha_peers(self, table):
        url = f"https://{self.fw_ip}/api/v2/monitor/system/ha-peer"
        payload = {}
        headers = {"Authorization": f"Bearer {FW_TOKEN}"}
        response_raw = requests.request(
            "GET", url, headers=headers, data=payload, verify=False
        )
        response_text = response_raw.text
        priority = -1
        result = {}
        response = response_raw.json()["results"]
        if not len(response) == 2:
            result["status"] = "FAILURE: "
            result[
                "message"
            ] = f"HA group does not have 2 firewalls. Please check the FW configurations"

        for peer in response:
            if peer["priority"] > priority:
                priority = peer["priority"]
        for peer in response:
            if peer["priority"] == priority and "fw00" in peer["hostname"]:
                result["status"] = "SUCCESS: "
                result["message"] = "FW00 is the primary firewall"
                break
            else:
                result["status"] = "FAILURE: "
                result[
                    "message"
                ] = f"FW00 is not the primary firewall. Please check the priorities"
        table.add_row([time.asctime(), result["status"], result["message"]])
        # # output=result["status"]+result["message"]
        # print(output)
        with open(
            f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.fw_ip}-{self.name}.log",
            "w",
        ) as result_file:
            result_file.write(table.get_string())
        return table

    def validate_ha_health(self, table):
        # import pdb
        # pdb.set_trace()
        connection = self.ssh_connection(username=username, password=password)
        output = connection.send_command("get system ha status")
        lines = output.strip().split("\n")
        check = {}
        result = {}
        for n, line in enumerate(lines):
            if "HA Health Status" in line:
                check[line.split(":")[0].strip()] = line.split(":")[1].strip()
            if "Configuration Status" in line:
                check[lines[n + 1].split(":")[0].strip()] = (
                    lines[n + 1].split(":")[1].strip()
                )
                check[lines[n + 2].split(":")[0].strip()] = (
                    lines[n + 1].split(":")[1].strip()
                )
        for line in check.values():
            if line in ["OK", "in-sync"] and check["HA Health Status"] == "OK":
                result["status"] = "SUCCESS: "
                result[
                    "message"
                ] = "Firewall HA Health status is OK and config is in-sync"
            elif check["HA Health Status"] == "OK":
                result["status"] = "FAILURE: "
                result[
                    "message"
                ] = "Firewall HA Health status is OK but config is NOT in-sync."
            else:
                result["status"] = "SUCCESS: "
                result[
                    "message"
                ] = "Firewall HA Health status is not OK and config is NOT in-sync."

        # output=result["status"]+result["message"]
        # print(output)
        table.add_row([time.asctime(), result["status"], result["message"]])
        with open(
            f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.fw_ip}-{self.name}.log",
            "w",
        ) as result_file:
            result_file.write(table.get_string())
        return table

    def validate_bgp_sessions(self, table):
        url = f"https://{self.fw_ip}/api/v2/monitor/router/ipv4?type=bgp"
        payload = {}
        result = {}
        headers = {"Authorization": f"Bearer {FW_TOKEN}"}
        response_raw = requests.request(
            "GET", url, headers=headers, data=payload, verify=False
        )
        response = response_raw.json()["results"]
        if len(response) == 5:
            result["status"] = "SUCCESS: "
            result["message"] = "Firewall has 5 active BGP sessions"
        else:
            result["status"] = "FAILURE: "
            result[
                "message"
            ] = f"Firewall has {len(response)} active connection. Please check firewall configurations"

        # output=result["status"]+result["message"]
        # print(output)
        table.add_row([time.asctime(), result["status"], result["message"]])
        with open(
            f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.fw_ip}-{self.name}.log",
            "w",
        ) as result_file:
            result_file.write(table.get_string())
        return table

    def validate_sim_card(self, table):
        connection = self.ssh_connection(username=username, password=password)
        output = connection.send_command("diagnose sys lte-modem sim-info")
        lines = output.strip().split("\n")
        sim_info = {}
        result = {}
        if "Modem not detected" in output:
            result["status"] = "FAILURE: "
            result["message"] = f"SIM card is NOT PRESENT"
        else:
            for i in lines:
                sim_info[i.split(":")[0].strip()] = i.split(":")[1].strip()
            if "_PRESENT" in sim_info["SIM state"]:
                if sim_info.get("Country") and sim_info.get("Network"):
                    result["status"] = "SUCCESS: "
                    result[
                        "message"
                    ] = f'SIM card present and registered to {sim_info["Country"]} - {sim_info["Network"]}'
                else:
                    result["status"] = "FAILURE: "
                    result[
                        "message"
                    ] = f"SIM card present and but not registered to any network"

        # output=result["status"]+result["message"]
        # print(output)
        table.add_row([time.asctime(), result["status"], result["message"]])
        with open(
            f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.fw_ip}-{self.name}.log",
            "w",
        ) as result_file:
            result_file.write(table.get_string())
        return table

    def validate_wwan_interface(self, table):
        url = f"https://{self.fw_ip}/api/v2/monitor/system/interface"
        payload = {}
        headers = {"Authorization": f"Bearer {FW_TOKEN}"}
        response_raw = requests.request(
            "GET", url, headers=headers, data=payload, verify=False
        )
        result = {"status": "", "message": ""}
        response = response_raw.json()["results"]
        if response["wwan"]["link"]:
            result["status"] = "SUCCESS: "
            result["message"] = "WWAN/LTE interface is UP"
        else:
            result["status"] = "FAILURE: "
            result["message"] = "WWAN/ LTE interface is DOWN"

        # output=result["status"]+result["message"]
        # print(output)
        table.add_row([time.asctime(), result["status"], result["message"]])
        with open(
            f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.fw_ip}-{self.name}.log",
            "w",
        ) as result_file:
            result_file.write(table.get_string())
        return table

    def validate_fw_policy(self, table):
        url = f"https://{self.fw_ip}/api/v2/cmdb/firewall/policy"
        payload = {}
        headers = CaseInsensitiveDict()
        headers["Authorization"] = f"token {GITHUB_TOKEN}"

        return_elmt = requests.get(
            "https://raw.githubusercontent.com/drivenets/NaaS-Ops/main/SITE_FINAL_V3/MF00_V3.J2",
            headers=headers,
        )

        # Parse the returned jinja template to get the lates firewall policy
        config = return_elmt.text
        index_policy = config.splitlines().index("config firewall policy")
        index_end = config.splitlines()[index_policy:].index("end")
        policy_config_raw = config.splitlines()[
            index_policy : index_policy + index_end + 1
        ]
        strip_all = lambda lst: [x.strip() for x in lst]
        strip_next = lambda lst: [x if not x == "next" else x for x in lst]
        replace_edit = lambda lst: [x.replace("edit", "policyid") for x in lst]
        policy_strip_all = strip_all(policy_config_raw)
        policy_with_next = strip_all(policy_strip_all)
        clean = strip_next(policy_with_next)
        remove_empty = lambda lst: list(filter(None, lst))
        clean = remove_empty(clean)
        clean = clean[1:-3]
        clean = replace_edit(clean)

        clean_dic = []
        temp_dict = OrderedDict()

        for i in clean:
            if "policyid" in i:
                if temp_dict:
                    clean_dic.append(temp_dict)
                temp_dict = {"policyid": int(i.split()[-1])}
            elif "set name" in i:
                temp_dict["name"] = i.split()[-1].strip('"')
            elif "set srcintf" in i:
                temp_dict["srcintf"] = [{"name": j.strip('"')} for j in i.split()[2:]]
                for k in temp_dict["srcintf"]:
                    k["q_origin_key"] = k["name"]
            elif "set dstintf" in i:
                yes_list = []
                for j in i.split()[2:]:
                    yes_dic = {"name": j.strip('"')}
                    yes_list.append(copy.deepcopy(yes_dic))
                temp_dict["dstintf"] = yes_list
                for k in temp_dict["dstintf"]:
                    k["q_origin_key"] = k["name"]
            elif "set srcaddr" in i:
                yes_list = []
                for j in i.split()[2:]:
                    yes_dic = {"name": j.strip('"')}
                    yes_list.append(copy.deepcopy(yes_dic))
                temp_dict["srcaddr"] = yes_list
                for k in temp_dict["srcaddr"]:
                    k["q_origin_key"] = k["name"]
            elif "set dstaddr" in i:
                yes_list = []
                for j in i.split()[2:]:
                    yes_dic = {"name": j.strip('"')}
                    yes_list.append(copy.deepcopy(yes_dic))
                temp_dict["dstaddr"] = yes_list
                for k in temp_dict["dstaddr"]:
                    k["q_origin_key"] = k["name"]
            elif "set action" in i:
                temp_dict["action"] = i.split()[-1]
            elif "set schedule" in i:
                temp_dict["schedule"] = i.split()[-1].strip('"')
            elif "set service" in i:
                temp_dict["service"] = [{"name": j.strip('"')} for j in i.split()[2:]]
                for k in temp_dict["service"]:
                    k["q_origin_key"] = k["name"]
        clean_dic.append(temp_dict)
        url = f"https://{self.fw_ip}/api/v2/cmdb/firewall/policy"
        payload = {}
        headers = {"Authorization": f"Bearer {FW_TOKEN}"}
        response_raw = requests.request(
            "GET", url, headers=headers, data=payload, verify=False
        )
        response = response_raw.json()["results"]
        result = {}
        # I will loop trough both dictionaries and try to validate if the elements of sot is in reply and has the same value
        for response_elmt in response:
            p = 0
            h = 0
            for sot_elmt in clean_dic:
                if not sot_elmt["policyid"] == response_elmt["policyid"]:
                    p += 1
                else:
                    for k in list(sot_elmt.keys()):
                        if response_elmt[k] == sot_elmt[k]:
                            continue
                        result[response_elmt["policyid"]] = {}
                        result[response_elmt["policyid"]]["status"] = "FAILURE: "
                        result[response_elmt["policyid"]][
                            "message"
                        ] = f'Policy {response_elmt["policyid"]} element {k.upper()} {response_elmt[k]} does not have the right value. it should be {sot_elmt[k]}'
                        h += 1
            if h == 0 and not p == len(clean_dic):
                result[response_elmt["policyid"]] = {}
                result[response_elmt["policyid"]]["status"] = "SUCCESS: "
                result[response_elmt["policyid"]][
                    "message"
                ] = f"Policy {response_elmt['policyid']} has the right configuration"
            if p == len(clean_dic):
                result[response_elmt["policyid"]] = {}
                result[response_elmt["policyid"]]["status"] = "FAILURE: "
                result[response_elmt["policyid"]][
                    "message"
                ] = f"Policy {response_elmt['policyid']} should not present"

        expected_policy = [item["policyid"] for item in clean_dic]
        configured_policy = [item["policyid"] for item in response]

        missing_policy = [
            item for item in expected_policy if item not in configured_policy
        ]

        for policy in missing_policy:
            result[policy] = {}
            result[policy]["status"] = "FAILURE: "
            result[policy][
                "message"
            ] = f"Policy {policy} is missing in the Firewall configuration"

        for id, value in result.items():
            # output=f'POLICY {id} - {value.get("status")} {value.get("message")}'
            table.add_row([time.asctime(), value["status"], value["message"]])
            # print(output)
        with open(
            f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.fw_ip}-{self.name}.log",
            "w",
        ) as result_file:
            result_file.write(table.get_string())
        return table


class TerminalServer:
    def __init__(self, ts_ip, name) -> None:
        self.ts_ip = ts_ip
        self.name = name

    def validate_port_mapping(self, table, site_id, terminal_server):
        remote_conn_pre = paramiko.SSHClient()
        remote_conn_pre.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        remote_conn_pre.connect(f"{self.ts_ip}", username=username, password=password)
        remote_conn = remote_conn_pre.invoke_shell()
        remote_conn.recv(10000).decode("utf-8")
        remote_conn.send("2\r\n\r")
        time.sleep(5)
        output = remote_conn.recv(10000).decode("utf-8")
        results = []
        result = {}
        service_node_id = terminal_server[2:4]
        expected_ts_ports_sn01 = [
            f"1. fw02.{site_id}",
            "10. ncp1.sn01",
            f"11. pdu02.{site_id}",
            f"12. pdu03.{site_id}",
            f"2. fw03.{site_id}",
            f"3. tor02.{site_id}",
            f"4. tor03.{site_id}",
            f"5. ncma0.sn01",
            f"6. ncmb0.sn01",
            f"7. ncf0.sn01",
            f"8. ncf1.sn01",
            f"9. ncp0.sn01",
        ]
        expected_ts_ports_sn00 = [
            f"1. fw00.{site_id}",
            "10. ncp1.sn00",
            f"11. pdu00.{site_id}",
            f"12. pdu01.{site_id}",
            f"2. fw01.{site_id}",
            f"3. tor00.{site_id}",
            f"4. tor01.{site_id}",
            f"5. ncma0.sn00",
            f"6. ncmb0.sn00",
            f"7. ncf0.sn00",
            f"8. ncf1.sn00",
            f"9. ncp0.sn00",
        ]
        elements = re.findall(r"\d+\.\s*\w+?\d*?\.\w+", output, flags=re.M)
        elements = list(set(elements))
        elements.sort()
        port_match = {"00": expected_ts_ports_sn00, "01": expected_ts_ports_sn01}
        if port_match[service_node_id] == elements:
            result["status"] = "SUCCESS: "
            result[
                "message"
            ] = "Terminal server port mappings and descriptions are as expected"
            results.append(result)
        else:
            missing_port_map = [
                item for item in port_match[service_node_id] if item not in elements
            ]
            for port in missing_port_map:
                result["status"] = "FAILURE: "
                result[
                    "message"
                ] = f"{port} is missing or mapping is not to the right port in terminal server"
                results.append(copy.deepcopy(result))

        for result in results:
            # output=result["status"]+result["message"]
            # print(output)
            table.add_row([time.asctime(), result["status"], result["message"]])
        with open(
            f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.ts_ip}-{self.name}.log",
            "w",
        ) as result_file:
            result_file.write(table.get_string())
        return table


class Pdu:
    def __init__(self, pdu_ip, name) -> None:
        self.pdu_ip = pdu_ip
        self.name = name

    def validate_outlet_mapping(self, site_id, name, table):
        commands = {"Schneider": "olName all\n", "Sentry": "list outlets\n"}
        # name="pdu00.chi00"
        # site_id="chi00"
        pdu_code = name[0:5] + "-" + "sn" + name[-2:]

        expected_match_pdu00_sn00 = [
            f"psu.mc00.{site_id}",
            "Free_Outlet_2",
            f"psu0.tor00.{site_id}",
            f"psu1.tor00.{site_id}",
            f"psu0.ncma0.sn00.{site_id}",
            f"psu0.ncp0.sn00.{site_id}",
            f"psu0.ncf1.sn00.{site_id}",
            f"psu0.ncf0.sn00.{site_id}",
            f"psu.fw00.{site_id}",
            "Free_Outlet_10",
            "Free_Outlet_11",
            f"psu0.ncmb0.sn00.{site_id}",
            f"psu0.ncp1.sn00.{site_id}",
            f"psu1.ncc1.sn00.{site_id}",
            f"psu1.ncc0.sn00.{site_id}",
            f"psu1.ncs0.sn00.{site_id}",
        ]

        expected_match_pdu01_sn00 = [
            f"psu.mc01.{site_id}",
            f"psu.ts00.{site_id}",
            f"psu0.tor01.{site_id}",
            f"psu1.tor01.{site_id}",
            f"psu1.ncma0.sn00.{site_id}",
            f"psu1.ncp0.sn00.{site_id}",
            f"psu1.ncf1.sn00.{site_id}",
            f"psu1.ncf0.sn00.{site_id}",
            f"psu.fw01.{site_id}",
            "Free_Outlet_10",
            "Free_Outlet_11",
            f"psu1.ncmb0.sn00.{site_id}",
            f"psu1.ncp1.sn00.{site_id}",
            f"psu2.ncc1.sn00.{site_id}",
            f"psu2.ncc1.sn00.{site_id}",
            f"psu2.ncs0.sn00.{site_id}",
        ]

        expected_match_pdu02_sn01 = [
            f"psu.mc00.{site_id}",
            "Free_Outlet_2",
            f"psu0.tor02.{site_id}",
            f"psu1.tor02.{site_id}",
            f"psu0.ncma0.sn01.{site_id}",
            f"psu0.ncp0.sn01.{site_id}",
            f"psu0.ncf1.sn01.{site_id}",
            f"psu0.ncf0.sn01.{site_id}",
            f"psu.fw02.{site_id}",
            "Free_Outlet_10",
            "Free_Outlet_11",
            f"psu0.ncmb0.sn01.{site_id}",
            f"psu0.ncp1.sn01.{site_id}",
            f"psu1.ncc1.sn01.{site_id}",
            f"psu1.ncc0.sn01.{site_id}",
            f"psu1.ncs0.sn01.{site_id}",
        ]

        expected_match_pdu03_sn01 = [
            f"psu.mc03.{site_id}",
            f"psu.ts01.{site_id}",
            f"psu0.tor03.{site_id}",
            f"psu1.tor03.{site_id}",
            f"psu1.ncma0.sn01.{site_id}",
            f"psu1.ncp0.sn01.{site_id}",
            f"psu1.ncf1.sn01.{site_id}",
            f"psu1.ncf0.sn01.{site_id}",
            f"psu.fw03.{site_id}",
            "Free_Outlet_10",
            "Free_Outlet_11",
            f"psu1.ncmb0.sn01.{site_id}",
            f"psu1.ncp1.sn01.{site_id}",
            f"psu2.ncc1.sn01.{site_id}",
            f"psu2.ncc1.sn01.{site_id}",
            f"psu2.ncs0.sn01.{site_id}",
        ]

        compare = {
            "pdu00-sn00": expected_match_pdu00_sn00,
            "pdu01-sn00": expected_match_pdu01_sn00,
            "pdu02-sn01": expected_match_pdu02_sn01,
            "pdu03-sn01": expected_match_pdu03_sn01,
        }

        remote_conn_pre = paramiko.SSHClient()
        remote_conn_pre.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        remote_conn_pre.connect(
            f"{self.pdu_ip}",
            username=f"{username}",
            password=f"{password}",
            allow_agent=False,
            look_for_keys=False,
            disabled_algorithms=dict(
                pubkeys=["rsa-sha2-512", "rsa-sha2-256"],
                keys=["rsa-sha2-512", "rsa-sha2-256"],
            ),
        )
        connection = remote_conn_pre.invoke_shell()
        output = connection.recv(10000).decode("utf-8")
        if "Schneider" in output:
            command = commands["Schneider"]
        else:
            command = commands["Sentry"]

        connection.send(command)
        time.sleep(2)
        output = connection.recv(10000).decode("utf-8")
        result = {}
        pattern = r"(?:\w+\.\w+\.\w+.\w+)|(?:Free_Outlet_\d+)"
        outlets = re.findall(pattern, output)
        if outlets == compare[pdu_code]:
            result["status"] = "SUCCESS: "
            result[
                "message"
            ] = f"{self.name.split('.')[0].upper()} outlet naming is as expected"
        else:
            missing_outlet_map = [
                item for item in compare[pdu_code] if item not in outlets
            ]
            if missing_outlet_map:
                result["status"] = "FAILURE: "
                result[
                    "message"
                ] = f"{missing_outlet_map} are missing in the {self.name.split('.')[0].upper()} configuration"
            else:
                result["status"] = "FAILURE: "
                result[
                    "message"
                ] = f"All outlets are configured but mapping is not correct for {self.name.split('.')[0].upper()}."

        # output=result['status']+result['message']
        table.add_row([time.asctime(), result["status"], result["message"]])
        # print(output)
        with open(
            f"/Users/muhammedsozer/Documents/AcceptanceAutomation/results/results-{self.pdu_ip}-{self.name}.log",
            "w",
        ) as result_file:
            result_file.write(table.get_string())
        return table


def upload_results_to_S3(filename, bucket, object_name=None):
    """Upload a file to an S3 bucket
    :param file_name: File to upload
    :param bucket: Bucket to upload to
    :param object_name: S3 object name. If not specified then file_name is used
    :return: True if file was uploaded, else False
    """

    # If S3 object_name was not specified, use file_name

    if object_name is None:
        object_name = os.path.basename(filename)

        # Upload the file
        s3_client = boto3.client(
            "s3",
            aws_secret_access_key=AWS_ACCESS_SECRET,
            aws_access_key_id=AWS_ACCESS_KEY,
        )

    os.chdir("/Users/muhammedsozer/Documents/AcceptanceAutomation/results")
    try:
        print(f"{filename} is attemped to upload to S3")
        s3_client.upload_file(filename, bucket, object_name)
        print(
            f"{filename} was uploaded to S3. You reach the file from https://s3.console.aws.amazon.com/s3/buckets/msozer-log-bucket?region=us-east-1&tab=objects"
        )
    except ClientError as e:
        logging.error(e)
        return False
    return True
