-- Multi-IP host identity.
-- A single logical device (same published hostname, e.g. a MacBook seen over
-- Wi-Fi + Ethernet, or a phone with privacy-MAC rotation) is kept in ONE Host
-- row. secondary_ips holds the extra IP addresses it was seen at; macs holds
-- its full MAC history so later scans/merges can recognise the device again.
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS secondary_ips INET[] NOT NULL DEFAULT '{}';
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS macs TEXT[] NOT NULL DEFAULT '{}';