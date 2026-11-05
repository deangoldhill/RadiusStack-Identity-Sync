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

# Screenshots
<img width="1621" height="524" alt="Screenshot 2026-11-05 195740" src="https://github.com/user-attachments/assets/fdb251be-fa6b-4d9b-b6ed-339b9ed8872b" />
<img width="1611" height="689" alt="Screenshot 2026-11-05 195823" src="https://github.com/user-attachments/assets/22ddaa8e-e19c-42c8-a9b2-fce4bd00f80a" />
<img width="1598" height="769" alt="Screenshot 2026-11-05 195911" src="https://github.com/user-attachments/assets/e0efa856-d792-43cf-90d2-4a46bf3ff156" />
<img width="1591" height="804" alt="Screenshot 2026-11-05 200026" src="https://github.com/user-attachments/assets/51db9765-6639-4300-a13e-b8d3bfb3d4c3" />

