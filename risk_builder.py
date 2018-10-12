import json
import requests
import investigate
import threatconnect
from datetime import datetime, timedelta


# Define configuration file
config_file = json.load(open("configs/config.json"))

# Call the investigate API object
investigate_api = config_file["investigate_api"]
inv = investigate.Investigate(investigate_api)


class OTX(object):

    base_url = "https://otx.alienvault.com:443/api/v1"

    def __init__(self):

        self.uris = {"reputation": "/indicators/IPv4/{}/reputation"}
        self.config_file = json.load(open("configs/config.json"))
        self.headers = self.config_file["alien_vault"]["X-OTX-API-KEY"]

    def get_request(self, uri):

        response = requests.get(uri, self.headers)
        resp_json = response.json()
        return resp_json

    def reputation(self, ip):
        # Pulls IP reputation from AlienVault API
        uri = OTX.base_url + self.uris["reputation"].format(ip)
        return self.get_request(uri)


def main():

    # Define start time
    startTime = datetime.now()

    # Make empty lists for storing IPs
    ips = []

    vetted_ips = []

    for ip in ips:

        # Check AlienVault API
        otx = OTX()
        results = otx.reputation(ip)

        # Set threat score at 0
        threat_score = 0

        # If results are not returned, move onto next iteration
        try:
            if results["reputation"] == None:
                continue
        except Exception as e:
            print("Error: {}".format(e))

        # Use threat score as base for building risk score
        threat_score += int(results["reputation"]["threat_score"])
        last_seen = results["reputation"]["last_seen"]
        threat_type = results["reputation"]["counts"]

        # Use the most recent date observed as a way to build the risk score
        yesterday = datetime.now() - timedelta(days=1)
        yesterday_formatted = yesterday.isoformat()
        if str(last_seen) < str(yesterday_formatted):
            threat_score += 2

        # If country is outside of operating countries, add a point to risk score
        country = results["reputation"]["country"]
        if country != "US (United States)":
            threat_score += 1

        # An IP hosting malicious domains becomes slightly more suspicious
        malicious_domains = inv.latest_domains(ip)
        if len(malicious_domains) > 0:
            threat_score += 1

        # Create the dictionary
        d = {}
        d["indicator"] = ip
        d["threat_score"] = threat_score
        d["last_seen"] = last_seen
        d["threat_type"] = threat_type
        d["country"] = country
        d["latest_domains"] = malicious_domains

        vetted_ips.append(d)

    print(json.dumps(vetted_ips, indent=4))
    print(datetime.now() - startTime)


if __name__ == "__main__":
    main()
