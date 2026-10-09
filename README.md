# RadiusStack Identity Sync

RadiusStack Identity Sync is a containorised serivice that feeds identities from the RadiusStack active session table, to firewalls for identity awareness.
It uses the logged in username and Framed-IP-Address attribute to populate the firewall's identity awareness table.
Supported firewall vendors include Check Point, Palo Alto, Fortinet, Sonicwall, Cisco, Watchguard and Forcepoint.

## Deployment
1. clone the repo
2. edit the .env and specify a password to login to the webui
3. run 'docker compose up -d --build'

## Configuration
1. login to the webui on http://[dockerhost]:8111
2. go to the settings tab and specify the RadiusStack URL, API key and tenant ID
3. Go to the firewalls tab, select the vendor and API details.
Review the debug log and statistics to troubleshoot.
