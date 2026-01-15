from email.message import EmailMessage
from datetime import datetime
import pprint
from ipwhois import IPWhois
from concurrent.futures import ThreadPoolExecutor, as_completed
import pycountry
import ipinfo
import requests
import json
import dns.resolver
import smtplib
import random, math
import bcrypt
import ipaddress
import socket
import whois
import nmap3
import tldextract


def validate_ip_address(ip: str):
    """
    Validated whether given string is an valid IP address or not. If it is a valid IP address then, it returns True
    otherwise False.
    """

    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def get_domain_from_ip(ip: str):
    """
    This function extracts domain from IP address whenever possible.
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return None


def get_ip_from_domain(domain: str):
    """
    This function extracts IP from domain name wherever possible.
    """

    try:
        return socket.gethostbyname(domain)
    except:
        return None


def command_dig(domain: str, result_details: dict, result_summary: dict):
    """
    This function executed dig command and generates output if input is a valid domain name.
    """
    try:
        resolver = dns.resolver.Resolver()
        # resolver.nameservers = [socket.gethostbyname('ns1.cisco.com')]
        # resolver.nameservers=[socket.gethostbyname('resolver2.opendns.com')]
        resolver.nameservers = ["8.8.8.8"]
        # answer = resolver.query(domain, 'CNAME')

        answer1 = resolver.resolve(domain)
        answer2 = resolver.resolve(domain, "ns")

        result1 = [val.to_text() for val in answer1][0]
        result2 = [val.to_text()[:-1] for val in answer2]

        result_details["General"]["Domain Name Resolution IP:"] = result1
        result_details["General"]["Nameservers:"] = {}
        for nameserver in result2:
            result_details["General"]["Nameservers:"][nameserver] = get_ip_from_domain(
                nameserver
            )
        return
    except:
        return


def command_whois_ip(ip: str, result_details: dict, result_summary: dict):
    """
    This function executes whois command return output of whois for IP address.
    """
    try:
        if "Whois" not in result_details:
            result_details["Whois"] = {}
        if "Whois" not in result_summary:
            result_summary["Whois"] = {}

        obj = IPWhois(ip)
        res = obj.lookup_whois()
        result_details["Whois"]["ASN"] = {}
        result_summary["Whois"]["ASN"] = {}

        # result_details["Whois"]["ASN"]["ASN Number:"] = res["asn"]
        # result_details["Whois"]["ASN"]["ASN Range:"] = res["asn_cidr"]
        # result_details["Whois"]["ASN"]["ASN Country Code:"] = res["asn_country_code"]
        result_details["Whois"]["ASN"]["ASN Date:"] = res["asn_date"]
        # result_details["Whois"]["ASN"]["ASN Description:"] = res["asn_description"]
        # result_details["Whois"]["ASN"]["ASN Registry:"] = res["asn_registry"]
        result_details["Whois"]["ASN"]["Nets:"] = res["nets"]

        result_summary["Whois"]["ASN"]["ASN Number:"] = res["asn"]
        result_summary["Whois"]["ASN"]["ASN Range:"] = res["asn_cidr"]
        result_summary["Whois"]["ASN"]["ASN Country Code:"] = res["asn_country_code"]
        # result_summary["Whois"]["ASN"]["ASN Date:"] = res["asn_date"]
        result_summary["Whois"]["ASN"]["ASN Description:"] = res["asn_description"]
        result_summary["Whois"]["ASN"]["ASN Registry:"] = res["asn_registry"]

        return
    except:
        return


def command_whois_domain(domain: str, result_details: dict, result_summary: dict):
    """
    This function executes whois command return output of whois for domain name.
    """

    try:
        if "Whois" not in result_details:
            result_details["Whois"] = {}
        if "Whois" not in result_summary:
            result_summary["Whois"] = {}

        whois_data = whois.whois(domain)

        result_details["Whois"]["Contact"] = {}
        result_details["Whois"]["Domain Info"] = {}
        result_details["Whois"]["Dates"] = {}

        result_summary["Whois"]["Contact"] = {}
        result_summary["Whois"]["Domain Info"] = {}
        # result_summary["Whois"]["Dates"] = {}

        # result_details["Whois"]["Contact"]["Address:"] = whois_data.get("address")
        # result_details["Whois"]["Contact"]["City:"] = whois_data.get("city")
        # result_details["Whois"]["Contact"]["Country:"] = whois_data.get("country")
        if isinstance(whois_data.get("creation_date"), list):
            result_details["Whois"]["Dates"]["Creation Date:"] = [
                i.strftime("%m/%d/%Y, %H:%M:%S")
                for i in whois_data.get("creation_date")
            ]
        else:
            result_details["Whois"]["Dates"]["Creation Date:"] = whois_data.get(
                "creation_date"
            ).strftime("%m/%d/%Y, %H:%M:%S")

        # result_details["Whois"]["Domain Info"]["DNSSEC:"] = whois_data.get("dnssec")
        # result_details["Whois"]["Contact"]["Domain Name:"] = whois_data.get("domain_name")
        result_details["Whois"]["Contact"]["Emails:"] = whois_data.get("emails")
        if isinstance(whois_data.get("expiration_date"), list):
            result_details["Whois"]["Dates"]["Expiration Date:"] = [
                i.strftime("%m/%d/%Y, %H:%M:%S")
                for i in whois_data.get("expiration_date")
            ]
        else:
            result_details["Whois"]["Dates"]["Expiration Date:"] = whois_data.get(
                "expiration_date"
            ).strftime("%m/%d/%Y, %H:%M:%S")

        # result_details["Whois"]["Domain Info"]["Name:"] = whois_data.get("name")
        result_details["Whois"]["Domain Info"]["Name Servers:"] = whois_data.get(
            "name_servers"
        )
        # result_details["Whois"]["Domain Info"]["Organisation:"] = whois_data.get("org")
        result_details["Whois"]["Contact"]["Referral Url:"] = whois_data.get(
            "referral_url"
        )
        # result_details["Whois"]["Domain Info"]["Registrar:"] = whois_data.get("registrar")
        result_details["Whois"]["Contact"]["State:"] = whois_data.get("state")
        if isinstance(whois_data.get("status"), list):
            result_details["Whois"]["Domain Info"]["Status:"] = whois_data.get("status")
        else:
            result_details["Whois"]["Domain Info"]["Status:"] = [
                whois_data.get("status")
            ]

        result_details["Whois"]["Contact"]["Whois Server:"] = whois_data.get(
            "whois_server"
        )
        if isinstance(whois_data.get("updated_date"), list):
            result_details["Whois"]["Dates"]["Updated Date:"] = [
                i.strftime("%m/%d/%Y, %H:%M:%S") for i in whois_data.get("updated_date")
            ]
        else:
            result_details["Whois"]["Dates"]["Updated Date:"] = whois_data.get(
                "updated_date"
            ).strftime("%m/%d/%Y, %H:%M:%S")

        result_summary["Whois"]["Contact"]["Address:"] = whois_data.get("address")
        result_summary["Whois"]["Contact"]["City:"] = whois_data.get("city")
        result_summary["Whois"]["Contact"]["Country:"] = whois_data.get("country")
        # if isinstance(whois_data.get("creation_date"), list):
        #     result_summary["Whois"]["Dates"]["Creation Date:"] = [
        #         i.strftime("%m/%d/%Y, %H:%M:%S")
        #         for i in whois_data.get("creation_date")
        #     ]
        # else:
        #     result_summary["Whois"]["Dates"]["Creation Date:"] = whois_data.get(
        #         "creation_date"
        #     ).strftime("%m/%d/%Y, %H:%M:%S")
        result_summary["Whois"]["Domain Info"]["DNSSEC:"] = whois_data.get("dnssec")
        result_summary["Whois"]["Contact"]["Domain Name:"] = whois_data.get(
            "domain_name"
        )
        # result_summary["Whois"]["Contact"]["Emails:"] = whois_data.get("emails")
        # if isinstance(whois_data.get("expiration_date"), list):
        #     result_summary["Whois"]["Dates"]["Expiration Date:"] = [
        #         i.strftime("%m/%d/%Y, %H:%M:%S")
        #         for i in whois_data.get("expiration_date")
        #     ]
        # else:
        #     result_summary["Whois"]["Dates"]["Expiration Date:"] = whois_data.get(
        #         "expiration_date"
        #     ).strftime("%m/%d/%Y, %H:%M:%S")
        result_summary["Whois"]["Domain Info"]["Name:"] = whois_data.get("name")
        # result_summary["Whois"]["Domain Info"]["Name Servers:"] = whois_data.get(
        #     "name_servers"
        # )
        result_summary["Whois"]["Domain Info"]["Organisation:"] = whois_data.get("org")
        # result_summary["Whois"]["Contact"]["Referral Url:"] = whois_data.get(
        #     "referral_url"
        # )
        result_summary["Whois"]["Domain Info"]["Registrar:"] = whois_data.get(
            "registrar"
        )
        # result_summary["Whois"]["Contact"]["State:"] = whois_data.get("state")
        # result_summary["Whois"]["Contact"]["Whois Server:"] = whois_data.get(
        #     "whois_server"
        # )
        # if isinstance(whois_data.get("updated_date"), list):
        #     result_summary["Whois"]["Dates"]["Updated Date:"] = [
        #         i.strftime("%m/%d/%Y, %H:%M:%S") for i in whois_data.get("updated_date")
        #     ]
        # else:
        #     result_summary["Whois"]["Dates"]["Updated Date:"] = whois_data.get(
        #         "updated_date"
        #     ).strftime("%m/%d/%Y, %H:%M:%S")

        return
    except:
        return


def nmap_scans(ip: str, result_details: dict, result_summary: dict):
    """
    This function scans ports of the target ip address.
    """

    # Host discovery
    nmap = nmap3.NmapHostDiscovery()

    result = nmap.scan_top_ports(ip, default=30)
    result_details["Nmap"] = {}
    result_summary["Nmap"] = {}

    if ip in result:
        result_details["Nmap"]["State:"] = result[ip]["state"]["state"]
        result_details["Nmap"]["Reason:"] = result[ip]["state"]["reason"]
        result_details["Nmap"]["Reason TTL:"] = result[ip]["state"]["reason_ttl"]
        if result[ip]["state"]["state"] == "up":
            if result[ip]["hostname"]:
                result_details["Nmap"]["Hostname"] = result[ip]["hostname"][0]["name"]
            result_details["Nmap"]["Runtime:"] = result["runtime"]["elapsed"]
            result_details["Nmap"]["Summary:"] = result["runtime"]["summary"]
            result_details["Nmap"]["Timestamp:"] = result["runtime"]["timestr"]
            result_details["Nmap"]["Scanner:"] = result["stats"]["scanner"]

        result_summary["Nmap"]["State"] = result[ip]["state"]["state"]

        result_details["Nmap"]["Ports"] = {}
        result_details["Nmap"]["Ports"]["open"] = {}
        result_details["Nmap"]["Ports"]["closed"] = {}
        result_details["Nmap"]["Ports"]["filtered"] = {}
        result_details["Nmap"]["Ports"]["unfiltered"] = {}

        result_summary["Nmap"]["Ports"] = {}
        result_summary["Nmap"]["Ports"]["open"] = {}
        # result_summary["Nmap"]["Ports"]["closed"] = {}
        # result_summary["Nmap"]["Ports"]["filtered"] = {}
        # result_summary["Nmap"]["Ports"]["unfiltered"] = {}

        for element in result[ip]["ports"]:
            if element["state"] == "open":
                result_summary["Nmap"]["Ports"][element["state"]][
                    element["portid"]
                ] = {}
                result_summary["Nmap"]["Ports"][element["state"]][element["portid"]][
                    "Protocol"
                ] = element["protocol"]
                result_summary["Nmap"]["Ports"][element["state"]][element["portid"]][
                    "Reason"
                ] = element["reason"]
                result_summary["Nmap"]["Ports"][element["state"]][element["portid"]][
                    "Service"
                ] = element["service"]["name"]

            result_details["Nmap"]["Ports"][element["state"]][element["portid"]] = {}
            result_details["Nmap"]["Ports"][element["state"]][element["portid"]][
                "Protocol"
            ] = element["protocol"]
            result_details["Nmap"]["Ports"][element["state"]][element["portid"]][
                "Reason"
            ] = element["reason"]
            result_details["Nmap"]["Ports"][element["state"]][element["portid"]][
                "Reason_TTL"
            ] = element["reason_ttl"]
            result_details["Nmap"]["Ports"][element["state"]][element["portid"]][
                "Service"
            ] = element["service"]["name"]

    return


def vpnapi(parameters: dict, result_details: dict, result_summary: dict):
    """
    This funciton queries vpnapi API and compiles the result.
    """
    try:
        # details["Location"]["https://vpnapi.io"] = {}
        if not (parameters["geoLocation"] or parameters["blackList"]):
            return

        api_key = "1a9e5f4c21ed47b5842fb11d9460db12"
        api_url = f"https://vpnapi.io/api/{parameters['ip']}"

        params = {"key": api_key}
        result = requests.get(api_url, params=params)
        result = result.content.decode()
        result = json.loads(result)
        result_details["Location"]["https://vpnapi.io"] = {}
        result_details["Location"]["https://vpnapi.io"]["Latitude:"] = result[
            "location"
        ]["latitude"]
        result_details["Location"]["https://vpnapi.io"]["Longitude:"] = result[
            "location"
        ]["longitude"]
        result_details["Location"]["https://vpnapi.io"]["City:"] = result["location"][
            "city"
        ]
        result_details["Location"]["https://vpnapi.io"]["Region:"] = result["location"][
            "region"
        ]
        result_details["Location"]["https://vpnapi.io"]["Country:"] = result[
            "location"
        ]["country"]

        key_city = result["location"]["city"]
        key_region = result["location"]["region"]
        key_country = result["location"]["country"]

        if result["location"]["city"]:
            if key_city in result_summary["Location"]["City:"]:
                result_summary["Location"]["City:"][key_city] += 1
            else:
                result_summary["Location"]["City:"][key_city] = 1
            result_summary["Location"]["City:"]["total"] += 1

        if result["location"]["region"]:
            if key_region in result_summary["Location"]["Region:"]:
                result_summary["Location"]["Region:"][key_region] += 1
            else:
                result_summary["Location"]["Region:"][key_region] = 1
            result_summary["Location"]["Region:"]["total"] += 1

        if result["location"]["country"]:
            if key_country in result_summary["Location"]["Country:"]:
                result_summary["Location"]["Country:"][key_country] += 1
            else:
                result_summary["Location"]["Country:"][key_country] = 1
            result_summary["Location"]["Country:"]["total"] += 1

        result_details["Location"]["https://vpnapi.io"]["Continent:"] = result[
            "location"
        ]["continent"]

        result_details["Security"]["https://vpnapi.io"] = {}
        result_details["Security"]["https://vpnapi.io"]["Is vpn?"] = result["security"][
            "vpn"
        ]
        result_details["Security"]["https://vpnapi.io"]["Is proxy?"] = result[
            "security"
        ]["proxy"]
        result_details["Security"]["https://vpnapi.io"]["Is tor?"] = result["security"][
            "tor"
        ]

        key_vpn = str(result["security"]["vpn"])
        key_proxy = str(result["security"]["proxy"])
        key_tor = str(result["security"]["tor"])

        result_summary["Security"]["Is vpn?"][key_vpn] += 1
        result_summary["Security"]["Is vpn?"]["total"] += 1

        result_summary["Security"]["Is proxy?"][key_proxy] += 1
        result_summary["Security"]["Is proxy?"]["total"] += 1

        result_summary["Security"]["Is tor?"][key_tor] += 1
        result_summary["Security"]["Is tor?"]["total"] += 1
        return
    except Exception:
        return


def abstract(parameters: dict, result_details: dict, result_summary: dict):
    """
    This funciton queries abstract API and compiles the result.
    """
    try:
        # details["apis"]["https://www.abstractapi.com/api/ip-geolocation-api"] = {}
        if not (parameters["geoLocation"] or parameters["blackList"]):
            return

        api_key = "3e23a9203357488e8962b0d2979f1dc2"
        api_url = "https://ipgeolocation.abstractapi.com/v1/"

        params = {"api_key": api_key, "ip_address": parameters["ip"]}

        result = requests.get(api_url, params=params)
        result = result.content.decode()
        result = json.loads(result)

        result_details["Location"][
            "https://www.abstractapi.com/api/ip-geolocation-api"
        ] = {}
        result_details["Location"][
            "https://www.abstractapi.com/api/ip-geolocation-api"
        ]["Latitude:"] = result["latitude"]
        result_details["Location"][
            "https://www.abstractapi.com/api/ip-geolocation-api"
        ]["Longitude:"] = result["longitude"]
        result_details["Location"][
            "https://www.abstractapi.com/api/ip-geolocation-api"
        ]["City:"] = result["city"]
        result_details["Location"][
            "https://www.abstractapi.com/api/ip-geolocation-api"
        ]["Region:"] = result["region"]
        result_details["Location"][
            "https://www.abstractapi.com/api/ip-geolocation-api"
        ]["Country:"] = result["country"]

        key_city = result["city"]
        key_region = result["region"]
        key_country = result["country"]

        if key_city:
            if key_city in result_summary["Location"]["City:"]:
                result_summary["Location"]["City:"][key_city] += 1
            else:
                result_summary["Location"]["City:"][key_city] = 1
            result_summary["Location"]["City:"]["total"] += 1

        if key_region:
            if key_region in result_summary["Location"]["Region:"]:
                result_summary["Location"]["Region:"][key_region] += 1
            else:
                result_summary["Location"]["Region:"][key_region] = 1
            result_summary["Location"]["Region:"]["total"] += 1

        if key_country:
            if key_country in result_summary["Location"]["Country:"]:
                result_summary["Location"]["Country:"][key_country] += 1
            else:
                result_summary["Location"]["Country:"][key_country] = 1
            result_summary["Location"]["Country:"]["total"] += 1

        result_details["Location"][
            "https://www.abstractapi.com/api/ip-geolocation-api"
        ]["Continent:"] = result["continent"]
        result_details["Location"][
            "https://www.abstractapi.com/api/ip-geolocation-api"
        ]["Postal Code:"] = result["postal_code"]
        result_details["Security"][
            "https://www.abstractapi.com/api/ip-geolocation-api"
        ] = {}
        result_details["Security"][
            "https://www.abstractapi.com/api/ip-geolocation-api"
        ]["Is vpn?"] = result["security"]["is_vpn"]

        key_vpn = str(result["security"]["is_vpn"])

        result_summary["Security"]["Is vpn?"][key_vpn] += 1
        result_summary["Security"]["Is vpn?"]["total"] += 1

        result_details["Security"][
            "https://www.abstractapi.com/api/ip-geolocation-api"
        ]["Connection"] = {}
        result_details["Security"][
            "https://www.abstractapi.com/api/ip-geolocation-api"
        ]["Connection"]["Connection Type:"] = result["connection"]["connection_type"]
        result_details["Security"][
            "https://www.abstractapi.com/api/ip-geolocation-api"
        ]["Connection"]["ISP:"] = result["connection"]["isp_name"]

        return
    except Exception:
        return


def getipintel(parameters: dict, result_details: dict, result_summary: dict):
    """
    This funciton queries getipintel API and compiles the result.
    """
    try:
        # details["apis"]["https://getipintel.net/free-proxy-vpn-tor-ip-lookup/#web"] = {}
        if not parameters["blackList"]:
            return

        api_url = "http://check.getipintel.net/check.php"

        params = {
            "ip": parameters["ip"],
            "contact": parameters["email"],
            "format": "json",
        }

        result = requests.get(api_url, params)
        result = result.content.decode()
        result = json.loads(result)
        result = float(result["result"])

        result_details["Security"][
            "https://getipintel.net/free-proxy-vpn-tor-ip-lookup/#web"
        ] = {}
        result_details["Security"][
            "https://getipintel.net/free-proxy-vpn-tor-ip-lookup/#web"
        ]["Probability of Bad Ip:"] = result
        return

    except Exception:
        return


def ipdetective(parameters: dict, result_details: dict, result_summary: dict):
    """
    This funciton queries ipdetective API and compiles the result.
    """
    try:
        # details["apis"]["https://ipdetective.io/search"] = {}
        if not parameters["blackList"]:
            return

        api_key = "eb445c1e-6b94-46d2-9441-a581efc6f9fd"
        api_url = f"https://api.ipdetective.io/ip/{parameters['ip']}"

        params = {"x-api-key": api_key, "info": "true"}

        result = requests.get(api_url, params)
        result = result.content.decode()
        result = json.loads(result)

        result_details["Location"]["https://ipdetective.io/search"] = {}
        result_details["Location"]["https://ipdetective.io/search"]["Country:"] = (
            result["country_name"]
        )
        result_details["Security"]["https://ipdetective.io/search"] = {}
        result_details["Security"]["https://ipdetective.io/search"]["Is bot?"] = result[
            "bot"
        ]

        key_bot = str(result["bot"])

        result_summary["Security"]["Is bot?"][key_bot] += 1
        result_summary["Security"]["Is bot?"]["total"] += 1

        return

    except Exception:
        return


def ipgeolocation(parameters: dict, result_details: dict, result_summary: dict):
    """
    This funciton queries ipgeolocation API and compiles the result.
    """
    try:
        # details["apis"]["https://ipgeolocation.io"] = {}
        if not parameters["geoLocation"]:
            return

        api_key = "33c882f7bf8c4f88bd208c2821b89966"
        params = {
            "apiKey": api_key,
            "ip": parameters["ip"],
        }
        api_url = "https://api.ipgeolocation.io/ipgeo"

        result = requests.get(api_url, params=params)
        result = result.content.decode()
        result = json.loads(result)

        result_details["Location"]["https://ipgeolocation.io"] = {}
        result_details["Location"]["https://ipgeolocation.io"]["Latitude:"] = result[
            "latitude"
        ]
        result_details["Location"]["https://ipgeolocation.io"]["Longitude:"] = result[
            "longitude"
        ]
        result_details["Location"]["https://ipgeolocation.io"]["City:"] = result["city"]
        result_details["Location"]["https://ipgeolocation.io"]["District:"] = result[
            "district"
        ]
        result_details["Location"]["https://ipgeolocation.io"]["Region:"] = result[
            "state_prov"
        ]
        result_details["Location"]["https://ipgeolocation.io"]["Country:"] = result[
            "country_name"
        ]

        key_city = result["city"]
        key_region = result["state_prov"]
        key_country = result["country_name"]

        if key_city:
            if key_city in result_summary["Location"]["City:"]:
                result_summary["Location"]["City:"][key_city] += 1
            else:
                result_summary["Location"]["City:"][key_city] = 1
            result_summary["Location"]["City:"]["total"] += 1

        if key_region:
            if key_region in result_summary["Location"]["Region:"]:
                result_summary["Location"]["Region:"][key_region] += 1
            else:
                result_summary["Location"]["Region:"][key_region] = 1
            result_summary["Location"]["Region:"]["total"] += 1

        if key_country:
            if key_country in result_summary["Location"]["Country:"]:
                result_summary["Location"]["Country:"][key_country] += 1
            else:
                result_summary["Location"]["Country:"][key_country] = 1
            result_summary["Location"]["Country:"]["total"] += 1

        result_details["Location"]["https://ipgeolocation.io"]["Postal Code:"] = result[
            "zipcode"
        ]
        result_details["Location"]["https://ipgeolocation.io"]["Continent:"] = result[
            "continent_name"
        ]
        result_details["Security"]["https://ipgeolocation.io"] = {}
        result_details["Security"]["https://ipgeolocation.io"]["ISP:"] = result["isp"]

        return

    except Exception:
        return


def my_ipinfo(parameters: dict, result_details: dict, result_summary: dict):
    """
    This funciton queries my_ipinfo API and compiles the result.
    """
    try:
        # results["apis"]["https://ipinfo.info/html/ip_checker.php"] = {}
        if not parameters["geoLocation"]:
            return

        access_token = "d36e598e28b3ed"

        handler = ipinfo.getHandler(access_token)
        result = handler.getDetails(parameters["ip"])
        result = result.all

        result_details["Location"]["https://ipinfo.info/html/ip_checker.php"] = {}
        result_details["Location"]["https://ipinfo.info/html/ip_checker.php"][
            "Latitude:"
        ] = result["latitude"]
        result_details["Location"]["https://ipinfo.info/html/ip_checker.php"][
            "Longitude:"
        ] = result["longitude"]
        result_details["Location"]["https://ipinfo.info/html/ip_checker.php"][
            "City:"
        ] = result["city"]
        result_details["Location"]["https://ipinfo.info/html/ip_checker.php"][
            "Region:"
        ] = result["region"]
        result_details["Location"]["https://ipinfo.info/html/ip_checker.php"][
            "Country:"
        ] = result["country_name"]

        key_city = result["city"]
        key_region = result["region"]
        key_country = result["country_name"]

        if key_city:
            if key_city in result_summary["Location"]["City:"]:
                result_summary["Location"]["City:"][key_city] += 1
            else:
                result_summary["Location"]["City:"][key_city] = 1
            result_summary["Location"]["City:"]["total"] += 1

        if key_region:
            if key_region in result_summary["Location"]["Region:"]:
                result_summary["Location"]["Region:"][key_region] += 1
            else:
                result_summary["Location"]["Region:"][key_region] = 1
            result_summary["Location"]["Region:"]["total"] += 1

        if key_country:
            if key_country in result_summary["Location"]["Country:"]:
                result_summary["Location"]["Country:"][key_country] += 1
            else:
                result_summary["Location"]["Country:"][key_country] = 1
            result_summary["Location"]["Country:"]["total"] += 1

        result_details["Location"]["https://ipinfo.info/html/ip_checker.php"][
            "Postal Code:"
        ] = result["postal"]
        result_details["Location"]["https://ipinfo.info/html/ip_checker.php"][
            "Continent:"
        ] = result["continent"]["name"]

        return

    except Exception:
        return


def ipqualityscore(parameters: dict, result_details: dict, result_summary: dict):
    """
    This funciton queries ipqualityscore API and compiles the result.
    """
    try:
        # results["apis"]["https://www.ipqualityscore.com"] = {}
        if not (parameters["geoLocation"] or parameters["blackList"]):
            return

        api_key = "NX2KekECrcsL2e1DFuBnGXXJBxtXEWVP"
        api_url = "https://www.ipqualityscore.com/api/json/ip/%s/%s" % (
            api_key,
            parameters["ip"],
        )
        params = {
            "user_language": "en",
            "strictness": 0,
            "allow_public_access_points": "true",
            "lighter_penalties": "false",
        }

        result = requests.get(api_url, params)
        result = result.content.decode()
        result = json.loads(result)

        result_details["Location"]["https://www.ipqualityscore.com"] = {}
        result_details["Location"]["https://www.ipqualityscore.com"]["Latitude:"] = (
            result["latitude"]
        )
        result_details["Location"]["https://www.ipqualityscore.com"]["Longitude:"] = (
            result["longitude"]
        )
        result_details["Location"]["https://www.ipqualityscore.com"]["City:"] = result[
            "city"
        ]
        result_details["Location"]["https://www.ipqualityscore.com"]["Region:"] = (
            result["region"]
        )
        result_details["Location"]["https://www.ipqualityscore.com"]["Postal Code:"] = (
            result["zip_code"]
        )
        result_details["Location"]["https://www.ipqualityscore.com"][
            "Country Code:"
        ] = result["country_code"]

        key_city = result["city"]
        key_region = result["region"]
        key_country = pycountry.countries.get(alpha_2=result["country_code"]).name

        if key_city:
            if key_city in result_summary["Location"]["City:"]:
                result_summary["Location"]["City:"][key_city] += 1
            else:
                result_summary["Location"]["City:"][key_city] = 1
            result_summary["Location"]["City:"]["total"] += 1

        if key_region:
            if key_region in result_summary["Location"]["Region:"]:
                result_summary["Location"]["Region:"][key_region] += 1
            else:
                result_summary["Location"]["Region:"][key_region] = 1
            result_summary["Location"]["Region:"]["total"] += 1

        if key_country:
            if key_country in result_summary["Location"]["Country:"]:
                result_summary["Location"]["Country:"][key_country] += 1
            else:
                result_summary["Location"]["Country:"][key_country] = 1
            result_summary["Location"]["Country:"]["total"] += 1

        result_details["Security"]["https://www.ipqualityscore.com"] = {}
        result_details["Security"]["https://www.ipqualityscore.com"]["Is vpn?"] = (
            result["vpn"]
        )
        result_details["Security"]["https://www.ipqualityscore.com"]["Is proxy?"] = (
            result["proxy"]
        )
        result_details["Security"]["https://www.ipqualityscore.com"]["Is tor?"] = (
            result["tor"]
        )
        result_details["Security"]["https://www.ipqualityscore.com"]["Is bot?"] = (
            result["is_crawler"]
        )
        result_details["Security"]["https://www.ipqualityscore.com"][
            "Is tor active?"
        ] = result["active_tor"]
        result_details["Security"]["https://www.ipqualityscore.com"][
            "Is vpn active?"
        ] = result["active_vpn"]
        # results['apis']["https://www.ipqualityscore.com"]["Security"]["Is bot active?"] = result[
        # "bot_status"
        # ]

        key_vpn = str(result["vpn"] or result["active_vpn"])
        key_proxy = str(result["proxy"])
        key_tor = str(result["tor"] or result["active_tor"])
        key_bot = str(result["is_crawler"])

        result_summary["Security"]["Is vpn?"][key_vpn] += 1
        result_summary["Security"]["Is vpn?"]["total"] += 1

        result_summary["Security"]["Is proxy?"][key_proxy] += 1
        result_summary["Security"]["Is proxy?"]["total"] += 1

        result_summary["Security"]["Is tor?"][key_tor] += 1
        result_summary["Security"]["Is tor?"]["total"] += 1

        result_summary["Security"]["Is bot?"][key_bot] += 1
        result_summary["Security"]["Is bot?"]["total"] += 1

        result_details["Security"]["https://www.ipqualityscore.com"][
            "Threat Score:"
        ] = result["fraud_score"]
        # details["Security"]["https://www.ipqualityscore.com"] = {}
        result_details["Security"]["https://www.ipqualityscore.com"]["Is mobile?"] = (
            result["mobile"]
        )

        return

    except Exception:
        return


def ipregistry(parameters: dict, result_details: dict, result_summary: dict):
    """
    This funciton queries ipregistry API and compiles the result.
    """
    try:
        # details["apis"]["https://ipregistry.co/docs/proxy-tor-threat-detection"] = {}
        if not (parameters["geoLocation"] or parameters["blackList"]):
            return

        api_key = "yn0ilhhues18zsuf"
        api_url = f"https://api.ipregistry.co/{parameters['ip']}"

        params = {
            "key": api_key,
        }

        result = requests.get(api_url, params=params)
        result = result.content.decode()
        result = json.loads(result)

        result_details["Location"][
            "https://ipregistry.co/docs/proxy-tor-threat-detection"
        ] = {}
        result_details["Location"][
            "https://ipregistry.co/docs/proxy-tor-threat-detection"
        ]["Latitude:"] = result["location"]["latitude"]
        result_details["Location"][
            "https://ipregistry.co/docs/proxy-tor-threat-detection"
        ]["Longitude:"] = result["location"]["longitude"]
        result_details["Location"][
            "https://ipregistry.co/docs/proxy-tor-threat-detection"
        ]["City:"] = result["location"]["city"]
        result_details["Location"][
            "https://ipregistry.co/docs/proxy-tor-threat-detection"
        ]["Region:"] = result["location"]["region"]["name"]
        result_details["Location"][
            "https://ipregistry.co/docs/proxy-tor-threat-detection"
        ]["Country:"] = result["location"]["country"]["name"]

        key_city = result["location"]["city"]
        key_region = result["location"]["region"]["name"]
        key_country = result["location"]["country"]["name"]

        if key_city:
            if key_city in result_summary["Location"]["City:"]:
                result_summary["Location"]["City:"][key_city] += 1
            else:
                result_summary["Location"]["City:"][key_city] = 1
            result_summary["Location"]["City:"]["total"] += 1

        if key_region:
            if key_region in result_summary["Location"]["Region:"]:
                result_summary["Location"]["Region:"][key_region] += 1
            else:
                result_summary["Location"]["Region:"][key_region] = 1
            result_summary["Location"]["Region:"]["total"] += 1

        if key_country:
            if key_country in result_summary["Location"]["Country:"]:
                result_summary["Location"]["Country:"][key_country] += 1
            else:
                result_summary["Location"]["Country:"][key_country] = 1
            result_summary["Location"]["Country:"]["total"] += 1

        result_details["Location"][
            "https://ipregistry.co/docs/proxy-tor-threat-detection"
        ]["Postal Code:"] = result["location"]["postal"]
        result_details["Location"][
            "https://ipregistry.co/docs/proxy-tor-threat-detection"
        ]["Continent:"] = result["location"]["continent"]["name"]
        result_details["Security"][
            "https://ipregistry.co/docs/proxy-tor-threat-detection"
        ] = {}
        result_details["Security"][
            "https://ipregistry.co/docs/proxy-tor-threat-detection"
        ]["Is vpn?"] = result["security"]["is_vpn"]
        result_details["Security"][
            "https://ipregistry.co/docs/proxy-tor-threat-detection"
        ]["Is proxy?"] = result["security"]["is_proxy"]
        result_details["Security"][
            "https://ipregistry.co/docs/proxy-tor-threat-detection"
        ]["Is tor?"] = result["security"]["is_tor"]
        result_details["Security"][
            "https://ipregistry.co/docs/proxy-tor-threat-detection"
        ]["Is tor exit node?"] = result["security"]["is_tor_exit"]
        result_details["Security"][
            "https://ipregistry.co/docs/proxy-tor-threat-detection"
        ]["Is relay?"] = result["security"]["is_relay"]
        result_details["Security"][
            "https://ipregistry.co/docs/proxy-tor-threat-detection"
        ]["Is threat?"] = result["security"]["is_threat"]
        result_details["Security"][
            "https://ipregistry.co/docs/proxy-tor-threat-detection"
        ]["Is abuser?"] = result["security"]["is_abuser"]
        result_details["Security"][
            "https://ipregistry.co/docs/proxy-tor-threat-detection"
        ]["Is attacker?"] = result["security"]["is_attacker"]
        result_details["Security"][
            "https://ipregistry.co/docs/proxy-tor-threat-detection"
        ]["Is bogon?"] = result["security"]["is_bogon"]
        result_details["Security"][
            "https://ipregistry.co/docs/proxy-tor-threat-detection"
        ]["Is anonymous?"] = result["security"]["is_anonymous"]
        result_details["Security"][
            "https://ipregistry.co/docs/proxy-tor-threat-detection"
        ]["Is cloud provider?"] = result["security"]["is_cloud_provider"]

        key_vpn = str(result["security"]["is_vpn"])
        key_proxy = str(result["security"]["is_proxy"])
        key_tor = str(result["security"]["is_tor"])

        result_summary["Security"]["Is vpn?"][key_vpn] += 1
        result_summary["Security"]["Is vpn?"]["total"] += 1

        result_summary["Security"]["Is proxy?"][key_proxy] += 1
        result_summary["Security"]["Is proxy?"]["total"] += 1

        result_summary["Security"]["Is tor?"][key_tor] += 1
        result_summary["Security"]["Is tor?"]["total"] += 1

        result_details["Security"][
            "https://ipregistry.co/docs/proxy-tor-threat-detection"
        ]["Connection"] = {}
        result_details["Security"][
            "https://ipregistry.co/docs/proxy-tor-threat-detection"
        ]["Connection"]["Mobile Country Code:"] = result["carrier"]["mcc"]
        result_details["Security"][
            "https://ipregistry.co/docs/proxy-tor-threat-detection"
        ]["Connection"]["Mobile Network Code:"] = result["carrier"]["mnc"]
        result_details["Security"][
            "https://ipregistry.co/docs/proxy-tor-threat-detection"
        ]["Connection"]["Carrier Name:"] = result["carrier"]["name"]

        return

    except Exception:
        return


def proxycheck(parameters: dict, result_details: dict, result_summary: dict):
    """
    This funciton queries proxycheck API and compiles the result.
    """
    try:
        # details["apis"]["https://proxycheck.io"] = {}
        if not (parameters["geoLocation"] or parameters["blackList"]):
            return

        api_key = "2n4198-426384-19h24d-g65124"
        api_url = f"https://proxycheck.io/v2/{parameters['ip']}"

        params = {
            "key": api_key,
            "vpn": 3,
            "asn": 1,
            "risk": 2,
            "port": 1,
            "seen": 1,
            # "days": 5
        }

        result = requests.get(api_url, params)
        result = result.content.decode()
        result = json.loads(result)
        result = result[parameters["ip"]]

        result_details["Location"]["https://proxycheck.io"] = {}
        result_details["Location"]["https://proxycheck.io"]["Latitude:"] = result[
            "latitude"
        ]
        result_details["Location"]["https://proxycheck.io"]["Longitude:"] = result[
            "longitude"
        ]
        result_details["Location"]["https://proxycheck.io"]["City:"] = result["city"]
        result_details["Location"]["https://proxycheck.io"]["Region:"] = result[
            "region"
        ]
        result_details["Location"]["https://proxycheck.io"]["Country:"] = result[
            "country"
        ]
        result_details["Location"]["https://proxycheck.io"]["Continent:"] = result[
            "continent"
        ]

        key_city = result["city"]
        key_region = result["region"]
        key_country = result["country"]

        if key_city:
            if key_city in result_summary["Location"]["City:"]:
                result_summary["Location"]["City:"][key_city] += 1
            else:
                result_summary["Location"]["City:"][key_city] = 1
            result_summary["Location"]["City:"]["total"] += 1

        if key_region:
            if key_region in result_summary["Location"]["Region:"]:
                result_summary["Location"]["Region:"][key_region] += 1
            else:
                result_summary["Location"]["Region:"][key_region] = 1
            result_summary["Location"]["Region:"]["total"] += 1

        if key_country:
            if key_country in result_summary["Location"]["Country:"]:
                result_summary["Location"]["Country:"][key_country] += 1
            else:
                result_summary["Location"]["Country:"][key_country] = 1
            result_summary["Location"]["Country:"]["total"] += 1

        result_details["Security"]["https://proxycheck.io"] = {}
        result_details["Security"]["https://proxycheck.io"]["Is vpn?"] = (
            result["vpn"] == "yes"
        )
        result_details["Security"]["https://proxycheck.io"]["Is proxy?"] = (
            result["proxy"] == "yes"
        )

        key_vpn = str(result["vpn"] == "yes")
        key_proxy = str(result["proxy"] == "yes")

        result_summary["Security"]["Is vpn?"][key_vpn] += 1
        result_summary["Security"]["Is vpn?"]["total"] += 1

        result_summary["Security"]["Is proxy?"][key_proxy] += 1
        result_summary["Security"]["Is proxy?"]["total"] += 1

        result_details["Security"]["https://proxycheck.io"]["Risk:"] = result["risk"]

        return

    except Exception:
        return


def neutrino(parameters: dict, result_details: dict, result_summary: dict):
    """
    This funciton queries neutrino API and compiles the result.
    """
    try:

        # details["apis"]["https://www.neutrinoapi.com"] = {}

        api_user = "Owl"
        api_key = "uVHZjVrDaudaqFOtTJ9UtEYslMmwiPL7MX6wzLItuWxHcF2k"

        if not (
            parameters["geoLocation"]
            or parameters["blackList"]
            # or parameters["reputation_check"]
        ):
            return

        if parameters["geoLocation"]:
            api_url = "https://neutrinoapi.net/ip-probe"
            params = {"User-ID": api_user, "API-Key": api_key, "ip": parameters["ip"]}
            response = requests.get(api_url, params=params)
            result = response.content.decode()
            result = json.loads(result)

            result_details["Location"]["https://www.neutrinoapi.com"] = {}
            result_details["Location"]["https://www.neutrinoapi.com"]["City:"] = result[
                "city"
            ]
            result_details["Location"]["https://www.neutrinoapi.com"]["Region:"] = (
                result["region"]
            )
            result_details["Location"]["https://www.neutrinoapi.com"]["Country:"] = (
                result["country"]
            )

            key_city = result["city"]
            key_region = result["region"]
            key_country = result["country"]

            if key_city:
                if key_city in result_summary["Location"]["City:"]:
                    result_summary["Location"]["City:"][key_city] += 1
                else:
                    result_summary["Location"]["City:"][key_city] = 1
                result_summary["Location"]["City:"]["total"] += 1

            if key_region:
                if key_region in result_summary["Location"]["Region:"]:
                    result_summary["Location"]["Region:"][key_region] += 1
                else:
                    result_summary["Location"]["Region:"][key_region] = 1
                result_summary["Location"]["Region:"]["total"] += 1

            if key_country:
                if key_country in result_summary["Location"]["Country:"]:
                    result_summary["Location"]["Country:"][key_country] += 1
                else:
                    result_summary["Location"]["Country:"][key_country] = 1
                result_summary["Location"]["Country:"]["total"] += 1

            result_details["Security"]["https://www.neutrinoapi.com"] = {}
            result_details["Security"]["https://www.neutrinoapi.com"]["Is vpn?"] = (
                result["is-vpn"]
            )
            result_details["Security"]["https://www.neutrinoapi.com"]["Is proxy?"] = (
                result["is-proxy"]
            )

            key_vpn = str(result["is-vpn"])
            key_proxy = str(result["is-proxy"])

            result_summary["Security"]["Is vpn?"][key_vpn] += 1
            result_summary["Security"]["Is vpn?"]["total"] += 1

            result_summary["Security"]["Is proxy?"][key_proxy] += 1
            result_summary["Security"]["Is proxy?"]["total"] += 1

            result_details["Security"]["https://www.neutrinoapi.com"]["Is bogon?"] = (
                result["is-bogon"]
            )
            result_details["Security"]["https://www.neutrinoapi.com"]["Is hosting?"] = (
                result["is-hosting"]
            )
            result_details["Security"]["https://www.neutrinoapi.com"]["Connection"] = {}
            result_details["Security"]["https://www.neutrinoapi.com"]["Connection"][
                "Is isp?"
            ] = result["is-isp"]

        if parameters["blackList"]:
            api_url = "https://neutrinoapi.net/ip-blocklist/"
            params = {
                "User-ID": api_user,
                "API-Key": api_key,
                "ip": parameters["ip"],
                "vpn-lookup": True,
            }
            response = requests.get(api_url, params=params)
            result = response.content.decode()
            result = json.loads(result)
            if "https://www.neutrinoapi.com" not in result_details["Security"]:
                result_details["Security"]["https://www.neutrinoapi.com"] = {}

                # result_details["Security"]["https://www.neutrinoapi.com"]["Is vpn?"] = (
                #     result_details["Security"]["https://www.neutrinoapi.com"]["Is vpn?"]
                #     or result["is-vpn"]
                # )

                # result_details["Security"]["https://www.neutrinoapi.com"]["Is proxy?"] = (
                #     result_details["Security"]["https://www.neutrinoapi.com"]["Is proxy?"]
                #     or result["is-proxy"]
                # )

            if "Is vpn?" in result_details["Security"]["https://www.neutrinoapi.com"]:
                result_details["Security"]["https://www.neutrinoapi.com"]["Is vpn?"] = (
                    result_details["Security"]["https://www.neutrinoapi.com"]["Is vpn?"]
                    or result["is-vpn"]
                )
            else:
                result_details["Security"]["https://www.neutrinoapi.com"]["Is vpn?"] = (
                    result["is-vpn"]
                )

            if "Is proxy?" in result_details["Security"]["https://www.neutrinoapi.com"]:
                result_details["Security"]["https://www.neutrinoapi.com"][
                    "Is proxy?"
                ] = (
                    result_details["Security"]["https://www.neutrinoapi.com"][
                        "Is proxy?"
                    ]
                    or result["is-proxy"]
                )
            else:
                result_details["Security"]["https://www.neutrinoapi.com"][
                    "Is proxy?"
                ] = result["is-proxy"]

            result_details["Security"]["https://www.neutrinoapi.com"]["Is tor?"] = (
                result["is-tor"]
            )
            result_details["Security"]["https://www.neutrinoapi.com"]["Is bot?"] = (
                result["is-bot"]
            )
            result_details["Security"]["https://www.neutrinoapi.com"]["Is dshield?"] = (
                result["is-dshield"]
            )
            result_details["Security"]["https://www.neutrinoapi.com"][
                "Is exploit bot?"
            ] = result["is-exploit-bot"]
            result_details["Security"]["https://www.neutrinoapi.com"][
                "Is hijacked?"
            ] = result["is-hijacked"]
            result_details["Security"]["https://www.neutrinoapi.com"]["Is malware?"] = (
                result["is-malware"]
            )
            result_details["Security"]["https://www.neutrinoapi.com"][
                "Is spam bot?"
            ] = result["is-spam-bot"]
            result_details["Security"]["https://www.neutrinoapi.com"]["Is spider?"] = (
                result["is-spider"]
            )
            result_details["Security"]["https://www.neutrinoapi.com"]["Is spyware?"] = (
                result["is-spyware"]
            )
            result_details["Security"]["https://www.neutrinoapi.com"][
                "Blocklist count:"
            ] = result["list-count"]
            result_details["Security"]["https://www.neutrinoapi.com"]["Blocklists"] = (
                result["blocklists"]
            )

            key_vpn = str(
                result_details["Security"]["https://www.neutrinoapi.com"]["Is vpn?"]
            )
            key_proxy = str(
                result_details["Security"]["https://www.neutrinoapi.com"]["Is proxy?"]
            )
            key_tor = str(result["is-tor"])
            key_bot = str(
                result["is-bot"]
                or result["is-spam-bot"]
                or result["is-spider"]
                or result["is-exploit-bot"]
            )

            result_summary["Security"]["Is vpn?"][key_vpn] += 1
            result_summary["Security"]["Is vpn?"]["total"] += 1

            result_summary["Security"]["Is proxy?"][key_proxy] += 1
            result_summary["Security"]["Is proxy?"]["total"] += 1

            result_summary["Security"]["Is tor?"][key_tor] += 1
            result_summary["Security"]["Is tor?"]["total"] += 1

            result_summary["Security"]["Is bot?"][key_bot] += 1
            result_summary["Security"]["Is bot?"]["total"] += 1

            # if parameters["reputation_check"]:
            api_url = "https://neutrinoapi.net/host-reputation/"
            params = {
                "User-ID": api_user,
                "API-Key": api_key,
                "host": parameters["ip"],
            }

            response = requests.get(api_url, params=params)
            result = response.content.decode()
            result = json.loads(result)

            pprint.pprint(result)

            if "https://www.neutrinoapi.com" not in result_details["Security"]:
                result_details["Security"]["https://www.neutrinoapi.com"] = {}

            result_details["Security"]["https://www.neutrinoapi.com"][
                "Blacklist count:"
            ] = result["list-count"]
            result_details["Security"]["https://www.neutrinoapi.com"][
                "Blacklisted"
            ] = []
            result_details["Security"]["https://www.neutrinoapi.com"][
                "Non_Blacklisted"
            ] = []
            for element in result["lists"]:
                if element["is-listed"]:
                    result_details["Security"]["https://www.neutrinoapi.com"][
                        "Blacklisted"
                    ].append(element)
                else:
                    result_details["Security"]["https://www.neutrinoapi.com"][
                        "Non_Blacklisted"
                    ].append(element)

        return

    except Exception:
        return


def abuse_ipdb(parameters: dict, result_details: dict, result_summary: dict):
    """
    This funciton queries abuseIPDB API and compiles the result.
    """
    try:

        # details["apis"]["https://www.abuseipdb.com"] = {}

        if not (
            parameters["geoLocation"]
            or parameters["blackList"]
            or parameters["reports"]
        ):
            return

        api_url = "https://api.abuseipdb.com/api/v2/check"
        params = {"ipAddress": parameters["ip"], "maxAgeInDays": "90", "verbose": True}
        api_headers = {
            "Accept": "application/json",
            "Key": "fca8293111eb587f0527d8b324053c71b3b03257ac50e078755262f28c1962e513a155d28ce9c24b",
        }
        response = requests.request(
            method="GET", url=api_url, headers=api_headers, params=params
        )
        result = response.content.decode()
        result = json.loads(result)
        result = result["data"]

        if parameters["geoLocation"]:
            result_details["Location"]["https://www.abuseipdb.com"] = {}
            result_details["Location"]["https://www.abuseipdb.com"]["Country:"] = (
                result["countryName"]
            )

            key_country = result["countryName"]

            if key_country:
                if key_country in result_summary["Location"]["Country:"]:
                    result_summary["Location"]["Country:"][key_country] += 1
                else:
                    result_summary["Location"]["Country:"][key_country] = 1
                result_summary["Location"]["Country:"]["total"] += 1

        if parameters["blackList"]:
            if "https://www.abuseipdb.com" not in result_details["Security"]:
                result_details["Security"]["https://www.abuseipdb.com"] = {}

            result_details["Security"]["https://www.abuseipdb.com"]["Is tor?"] = result[
                "isTor"
            ]
            result_details["Security"]["https://www.abuseipdb.com"][
                "Abuse Confidence Score:"
            ] = result["abuseConfidenceScore"]
            result_details["Security"]["https://www.abuseipdb.com"][
                "Is WhiteListed?"
            ] = result["isWhitelisted"]
            result_details["Security"]["https://www.abuseipdb.com"]["Connection"] = {}
            result_details["Security"]["https://www.abuseipdb.com"]["Connection"][
                "ISP:"
            ] = result["isp"]
            result_details["Security"]["https://www.abuseipdb.com"]["Connection"][
                "Usage Type:"
            ] = result["usageType"]

            key_tor = str(result["isTor"])

            result_summary["Security"]["Is tor?"][key_tor] += 1
            result_summary["Security"]["Is tor?"]["total"] += 1
            result_summary["Security"]["Abuse Confidence Score:"] = result[
                "abuseConfidenceScore"
            ]

        if parameters["reports"]:
            # if "https://www.abuseipdb.com" not in details["Reports"]:
            result_details["Reports"]["https://www.abuseipdb.com"] = {}
            result_details["Reports"]["https://www.abuseipdb.com"][
                "Last Reported At:"
            ] = result["lastReportedAt"]
            result_details["Reports"]["https://www.abuseipdb.com"]["Total Reports:"] = (
                result["totalReports"]
            )
            result_details["Reports"]["https://www.abuseipdb.com"]["Records"] = result[
                "reports"
            ]
            if "Reports" not in result_summary:
                result_summary["Reports"] = []
            result_summary["Reports"].extend(result["reports"])

    except Exception as e:
        return


def is_valid_domain(domain):
    # Check if the domain contains only alphanumeric characters and hyphens
    if not domain.replace("-", "").replace(".", "").isalnum():
        return False

    # Check if the domain doesn't end with a period
    if domain.endswith("."):
        return False

    return True


def dns_history(parameters: dict, result_details: dict, result_summary: dict):
    """
    This function queries security trails and extracts ips and domain names.
    """

    try:

        if not (parameters["dns_history"]):
            return

        if not is_valid_domain(parameters["domain"]):
            return

        domain_info = tldextract.extract(parameters["domain"])
        apex_domain = f"{domain_info.domain}.{domain_info.suffix}"

        api_url = "https://api.securitytrails.com/v1/query/scroll"
        sql_query = f'SELECT domain.hostname, dns.a.old, dns.a.value, dns.a.updated, ip.asn.owner, ip.asn.ip_block, ip.detail.ip_block FROM hosts WHERE domain.apex = "{apex_domain}"'
        payload = {"query": sql_query}
        api_headers = {
            "Content-Type": "application/json",
            "APIKEY": "Cn6VHeORjcNLA5bVZ9SKogDFsobMsSZv",
        }
        response = requests.post(api_url, json=payload, headers=api_headers)
        result = response.content.decode()
        result = json.loads(result)
        pprint.pprint(result)

        for record in result["records"]:
            if not record["dns"]["a"]["updated"]:
                continue

            record["dns"]["a"]["old"].append({"value": record["dns"]["a"]["value"]})
            ips = sorted(
                list(
                    set(
                        [
                            item["ip"]
                            for value in record["dns"]["a"]["old"]
                            for item in value["value"]
                        ]
                    )
                )
            )
            asn_ip_block = list(
                set(
                    record["ip"]["asn"]["ip_block"]
                    if record["ip"]["asn"]["ip_block"]
                    else []
                )
            )
            details_ip_block = list(
                set(
                    record["ip"]["detail"]["ip_block"]
                    if record["ip"]["detail"]["ip_block"]
                    else []
                )
            )
            owners = list(
                set(
                    record["ip"]["asn"]["owner"] if record["ip"]["asn"]["owner"] else []
                )
            )
            dt = datetime.strptime(record["dns"]["a"]["updated"], "%Y-%m-%dT%H:%M:%SZ")
            recorded_at = dt.strftime("%B %d, %Y %I:%M:%S %p UTC")
            new_record = {
                "IPs": ips,
                "ASN IP Block": asn_ip_block,
                "ARIA IP Block": details_ip_block,
                "Owner": owners,
                "Recorded At": recorded_at,
            }

            if (
                new_record["IPs"]
                or new_record["ASN IP Block"]
                or new_record["ARIA IP Block"]
            ):
                result_details["DNS History"].append(new_record)

        result_details["DNS History"].sort(
            key=lambda x: datetime.strptime(
                x["Recorded At"], "%B %d, %Y %I:%M:%S %p UTC"
            ),
            reverse=True,
        )

        result_summary["DNS History"] = result_details["DNS History"]
        return

    except Exception as e:
        return


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf8")


def check_password(password: bytes, hashed_password: bytes) -> bool:
    return bcrypt.checkpw(password, hashed_password)


def send_otp(purpose: str, usermail: str) -> str:
    """
    send_otp(purpose, usermail)

    purpose is the message for subject in the mail sent to usermail containing otp.
    """

    otp = "123456"

    return otp


def search_database(
    parameters: dict, result_details: dict, result_summary: dict, collection_handle: any
):
    if (
        not parameters["geoLocation"]
        and not parameters["blackList"]
        and not parameters["reports"]
        and not parameters["dns_history"]
    ):
        parameters["geoLocation"] = True
        parameters["blackList"] = True
        parameters["reports"] = True
        parameters["dns_history"] = True

    if parameters["geoLocation"]:
        document = collection_handle.find_one(
            {
                "$or": [{"ip": parameters["ip"]}, {"domain": parameters["domain"]}],
                "result_summary.Location": {"$ne": None},
            },
            None,
            sort=[("timestamp", -1)],
        )

        if document:
            result_summary["Location"] = document["result_summary"]["Location"]
            result_details["Location"] = document["result_details"]["Location"]
            parameters["geoLocation"] = False

    if parameters["blackList"]:
        document = collection_handle.find_one(
            {
                "$or": [{"ip": parameters["ip"]}, {"domain": parameters["domain"]}],
                "result_summary.Security": {"$ne": None},
                "$or": [
                    {"params.blackList": True},  # don't comment this otherwise it will
                    #   include only security featues found with location
                    # {"params.reputation_check": True},
                ],
            },
            None,
            sort=[("timestamp", -1)],
        )

        if document:
            result_summary["Security"] = document["result_summary"]["Security"]
            result_details["Security"] = document["result_details"]["Security"]
            parameters["blackList"] = False
        else:
            document = collection_handle.find_one(
                {
                    "$or": [{"ip": parameters["ip"]}, {"domain": parameters["domain"]}],
                    "result_summary.Security": {"$ne": None},
                },
                None,
                sort=[("timestamp", -1)],
            )
            if document:
                result_summary["Security"] = document["result_summary"]["Security"]
                result_details["Security"] = document["result_details"]["Security"]
                parameters["blackList"] = False

    # document = collection_handle.find_one(
    #     {
    #         "$or": [{"ip": parameters["ip"]}, {"domain": parameters["domain"]}],
    #         "result_summary.Nmap": {"$ne": None},
    #     },
    #     None,
    #     sort=[("timestamp", -1)],
    # )

    # if document:
    #     result_summary["Nmap"] = document["result_summary"]["Nmap"]
    #     result_details["Nmap"] = document["result_details"]["Nmap"]

    if parameters["reports"]:
        document = collection_handle.find_one(
            {
                "$or": [{"ip": parameters["ip"]}, {"domain": parameters["domain"]}],
                "result_summary.Reports": {"$ne": None},
            },
            None,
            sort=[("timestamp", -1)],
        )

        if document:
            result_summary["Reports"] = document["result_summary"]["Reports"]
            result_details["Reports"] = document["result_details"]["Reports"]
            parameters["reports"] = False

    if parameters["dns_history"]:
        document = collection_handle.find_one(
            {
                "$or": [{"ip": parameters["ip"]}, {"domain": parameters["domain"]}],
                "result_summary.DNS History": {"$ne": None},
            },
            None,
            sort=[("timestamp", -1)],
        )

        if document:
            result_summary["DNS History"] = document["result_summary"]["DNS History"]
            result_details["DNS History"] = document["result_details"]["DNS History"]
            parameters["dns_history"] = False

    return


def compute_results(user_email: str, parameters: dict, collection_handle: any):
    """
    This function handles user query and updates logs in the database after querying different APIs.
    data:
        user_email: string
        ip_domain: string
        geoLocation: bool
        blackList: bool
        portScan: bool
        reports: bool
    """

    query_time = datetime.now()
    ip_domain = parameters["ip_domain"].strip()

    result_details = {}
    result_summary = {}

    result_details["General"] = {}
    result_summary["General"] = {}

    if validate_ip_address(ip_domain):
        parameters["ip"] = ip_domain
        parameters["domain"] = get_domain_from_ip(ip_domain)
        command_whois_ip(parameters["ip"], result_details, result_summary)
        command_whois_domain(parameters["domain"], result_details, result_summary)
    else:
        parameters["domain"] = ip_domain
        ip_domain = get_ip_from_domain(ip_domain)
        parameters["ip"] = ip_domain
        command_whois_domain(parameters["domain"], result_details, result_summary)
        command_whois_ip(parameters["ip"], result_details, result_summary)

    command_dig(parameters["domain"], result_details, result_summary)

    result_summary["General"]["IP"] = parameters["ip"]
    result_summary["General"]["Domain"] = parameters["domain"]

    params = parameters.copy()

    if parameters["searchDatabase"]:
        search_database(parameters, result_details, result_summary, collection_handle)

    if parameters["portScan"]:
        nmap_scans(parameters["ip"], result_details, result_summary)

    if parameters["geoLocation"]:
        result_details["Location"] = {}
        result_summary["Location"] = {}
        result_summary["Location"]["City:"] = {}
        result_summary["Location"]["City:"]["total"] = 0
        result_summary["Location"]["Country:"] = {}
        result_summary["Location"]["Country:"]["total"] = 0
        result_summary["Location"]["Region:"] = {}
        result_summary["Location"]["Region:"]["total"] = 0
        result_summary["Location"]["Timestamp:"] = query_time

    # or data["reputation_check"]
    if (
        parameters["geoLocation"]
        or parameters["blackList"]
        or parameters["reports"]
        or parameters["dns_history"]
    ):
        result_details["Security"] = {}
        result_details["Reports"] = {}
        result_details["DNS History"] = []

        result_summary["Security"] = {}
        result_summary["Security"]["Is vpn?"] = {}
        result_summary["Security"]["Is vpn?"]["True"] = 0
        result_summary["Security"]["Is vpn?"]["False"] = 0
        result_summary["Security"]["Is vpn?"]["total"] = 0

        result_summary["Security"]["Is proxy?"] = {}
        result_summary["Security"]["Is proxy?"]["True"] = 0
        result_summary["Security"]["Is proxy?"]["False"] = 0
        result_summary["Security"]["Is proxy?"]["total"] = 0

        result_summary["Security"]["Is tor?"] = {}
        result_summary["Security"]["Is tor?"]["True"] = 0
        result_summary["Security"]["Is tor?"]["False"] = 0
        result_summary["Security"]["Is tor?"]["total"] = 0

        result_summary["Security"]["Is bot?"] = {}
        result_summary["Security"]["Is bot?"]["True"] = 0
        result_summary["Security"]["Is bot?"]["False"] = 0
        result_summary["Security"]["Is bot?"]["total"] = 0

        result_summary["Security"]["Abuse Confidence Score:"] = 0
        result_summary["Security"]["Timestamp:"] = query_time
        result_summary["Reports"] = []
        result_summary["DNS History"] = []

        with ThreadPoolExecutor() as executor:
            futures = [
                executor.submit(vpnapi, parameters, result_details, result_summary),
                executor.submit(abstract, parameters, result_details, result_summary),
                executor.submit(getipintel, parameters, result_details, result_summary),
                executor.submit(
                    ipdetective, parameters, result_details, result_summary
                ),
                executor.submit(
                    ipgeolocation, parameters, result_details, result_summary
                ),
                executor.submit(my_ipinfo, parameters, result_details, result_summary),
                executor.submit(
                    ipqualityscore, parameters, result_details, result_summary
                ),
                executor.submit(ipregistry, parameters, result_details, result_summary),
                executor.submit(proxycheck, parameters, result_details, result_summary),
                executor.submit(neutrino, parameters, result_details, result_summary),
                executor.submit(abuse_ipdb, parameters, result_details, result_summary),
                executor.submit(dns_history, parameters, result_details, result_summary),
            ]

            # dns_history(parameters, result_details, result_summary)

            for future in as_completed(futures):
                try:
                    result = future.result()
                    print(f"Task completed with result: {result}")
                except Exception as e:
                    print(f"Task generated an exception: {e}")

        # vpnapi(parameters, result_details, result_summary)
        # abstract(parameters, result_details, result_summary)
        # getipintel(parameters, result_details, result_summary)
        # ipdetective(parameters, result_details, result_summary)
        # ipgeolocation(parameters, result_details, result_summary)
        # my_ipinfo(parameters, result_details, result_summary)
        # ipqualityscore(parameters, result_details, result_summary)
        # ipregistry(parameters, result_details, result_summary)
        # proxycheck(parameters, result_details, result_summary)
        # neutrino(parameters, result_details, result_summary)
        # abuse_ipdb(parameters, result_details, result_summary)

        if parameters["geoLocation"]:
            for key1, value1 in result_summary["Location"].items():
                if key1 == "Timestamp:":
                    continue
                for key2 in value1:
                    if key2 != "total":
                        if value1["total"]:
                            value1[key2] = (
                                f"{round( (value1[key2] / value1['total']) * 100, 2)} %"
                            )
                        else:
                            value1[key2] = f"0 %"
                if "total" in value1:
                    del value1["total"]

        for key1, value1 in result_summary["Security"].items():
            if key1 == "Timestamp:" or key1 == "Abuse Confidence Score:":
                continue
            for key2 in value1:
                if key2 != "total":
                    if value1["total"]:
                        value1[key2] = (
                            f"{round((value1[key2] / value1['total']) * 100, 2)} %"
                        )
                    else:
                        value1[key2] = f"0 %"
            if "total" in value1:
                del value1["total"]

    collection_handle.insert_one(
        {
            # "name": request.session["name"],
            # "email": request.session["email"],
            "email": user_email,
            "ip": parameters["ip"],
            "domain": parameters["domain"],
            "params": params,
            "timestamp": query_time,
            "result_details": result_details,
            "result_summary": result_summary,
        }
    )

    if "Location" in result_summary:
        result_summary["Location"]["Timestamp:"] = result_summary["Location"][
            "Timestamp:"
        ].strftime("%b %d %Y, %H:%M:%S")
    if "Security" in result_summary:
        result_summary["Security"]["Timestamp:"] = result_summary["Security"][
            "Timestamp:"
        ].strftime("%b %d %Y, %H:%M:%S")

    return result_details, result_summary


# 104.244.72.115
