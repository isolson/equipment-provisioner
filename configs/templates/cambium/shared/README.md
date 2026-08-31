# Cambium shared profiles

The active shared SM profile is installed at:

`/var/lib/provisioner/repo/configs/templates/cambium/shared/5.11.1/SM/default.json`

The file is a protected runtime asset. Upload it from `/files` as a **Field
deployment export** with role **SM** and scope **Shared baseline**. The upload
keeps the original export in private runtime storage and activates a normalized
copy atomically.

The shared profile must contain these policy fields:

- management VLAN enabled, VLAN `12`
- management address by DHCP
- DNS from DHCP
- syslog `100.126.15.28`, UDP `514`, mask `31`
- internal cnMaestro host `cnmaestro.infra.treehouse.mn`
- SSH enabled and Telnet disabled
- scan mask `51` in the shared profile
- antenna gain `17` dBi

Do not put a site SSID, center frequency, static address, hostname, serial
number, or MAC address in the shared SM profile. Set SSID and site identity in
the later AP, PTP, or custom setup.

AP, PTP-A, and PTP-B exports are separate family profiles. They are not
substitutes for the shared SM profile.

This tracked README contains no credentials or export data. Runtime field
exports may contain operational secrets. The API reports metadata only and
does not return protected profile content.
