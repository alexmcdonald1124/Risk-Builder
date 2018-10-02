import json
import requests
import investigate
import threatconnect
from datetime import datetime, timedelta

# Define configuration file
config_file = json.load(open('configs/config.json'))

# Call the investigate API object
investigate_api = config_file['investigate_api']
inv = investigate.Investigate(investigate_api)


def main():

    # Make lists for storing IP lists
    ips = []
    vetted_ips = []

    for ip in ips:

        # Call AlienVault API for reputation information
        response = requests.get(config_file['alien_vault']['base_url'] + '/indicators/IPv4/{}/reputation'.format(ip), 
            headers=config_file['alien_vault'])
        results = response.json()

        # Set threat score at 0
        threat_score = 0

        # If results are not returned, move onto next iteration
        if results['reputation'] == None:
            continue

        # Use threat score as base for building risk score
        threat_score += int(results['reputation']['threat_score'])
        last_seen = results['reputation']['last_seen']
        threat_type = results['reputation']['counts']

        # Use the most recent date observed as a way to build the risk score
        yesterday = datetime.now() - timedelta(days=1)
        yesterday_formatted = yesterday.isoformat()
        if str(last_seen) < str(yesterday_formatted):
            threat_score += 2

        # If country is outside of operating countries, add a point to risk score
        country = results['reputation']['country']
        if country != 'US (United States)':
            threat_score += 1

        # An IP hosting malicious domains becomes slightly more suspicious
        malicious_domains = inv.latest_domains(ip)
        if len(malicious_domains) > 0:
            threat_score += 1

        # Create the dictionary
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