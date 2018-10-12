import json
import requests
from urllib.parse import urljoin


class OTX(object):

    base_url = "https://otx.alienvault.com:443/api/v1"

    def __init__(self):

        self.uris = {"reputation": "/indicators/IPv4/{}/reputation"}
        self.config_file = json.load(open("configs/config.json"))
        self.headers = self.config_file["alien_vault"]["X-OTX-API-KEY"]

    def get_request(self, uri):

        response = requests.get(urljoin(OTX.base_url, uri), self.headers)
        resp_json = response.json()
        return resp_json

    def reputation(self, ip):
        # Pulls IP reputation from AlienVault API
        uri = self.uris["reputation"].format(ip)
        return self.get_request(uri)
