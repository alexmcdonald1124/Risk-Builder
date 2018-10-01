import json
import requests
import investigate
import threatconnect
from datetime import datetime, timedelta

# Define configuration file
config_file = json.load(open('configs/config.json'))

investigate_api = config_file['investigate_api']
inv = investigate.Investigate(investigate_api)

ips = ['104.223.190.147',
'206.136.131.3',
'112.127.77.125',
'31.186.169.41',
'50.63.202.2',
'63.128.92.145',
'112.78.125.29',
'51.38.80.70',
'46.249.43.105',
'194.58.56.127',
'119.23.127.213',
'46.28.105.107',
'194.58.56.15',
'46.28.2.13',
'123.254.108.81',
'91.236.242.118',
'95.216.161.60',
'133.242.195.32',
'23.89.20.107',
'173.233.72.39',
'157.112.183.75',
'159.69.42.212',
'159.69.83.207',
'150.95.255.38',
'93.174.4.8',
'62.129.200.14',
'162.210.102.66',
'62.149.128.151',
'62.149.128.154',
'202.181.97.76',
'62.149.128.157',
'103.224.212.222',
'112.121.187.246',
'62.149.128.160',
'194.87.109.215',
'62.149.128.163',
'192.147.0.118',]

vetted_ips = []

def main():

    for ip in ips:

        response = requests.get(config_file['alien_vault']['base_url'] + '/indicators/IPv4/{}/reputation'.format(ip), 
            headers=config_file['alien_vault'])
        results = response.json()

        threat_score = 0

        if results['reputation'] == None:
            continue

        threat_score += int(results['reputation']['threat_score'])
        last_seen = results['reputation']['last_seen']
        threat_type = results['reputation']['counts']

        yesterday = datetime.now() - timedelta(days=1)
        yesterday_formatted = yesterday.isoformat()
        if str(last_seen) < str(yesterday_formatted):
            threat_score += 2

        country = results['reputation']['country']
        if country != 'US (United States)':
            threat_score += 1

        malicious_domains = inv.latest_domains(ip)
        if len(malicious_domains) > 0:
            threat_score += 1

        d = {}
        d['indicator'] = ip
        d['threat_score'] = threat_score
        d['last_seen'] = last_seen
        d['threat_type'] = threat_type
        d['country'] = country
        d['latest_domains'] = malicious_domains

        vetted_ips.append(d)

    print(json.dumps(vetted_ips, indent=4))


if __name__ == '__main__':
    main()