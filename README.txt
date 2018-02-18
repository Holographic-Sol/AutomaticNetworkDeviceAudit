NDA. Designed to map network devices connected to target gateway &
then perform data analysis plus logging when needed.

Configuration:
The config file must be configured as follows. Order is irrelevent.

TARGET: 192.168.0.0
ALLOW: hostname  ip  mac  vendor  port-service-state  port-service-state

Specify a gateway in either IPv4 or hostname format.
Specify known devices and device details, add as many as you like.


This program is designed to scan a local network and compare detailed
scan results with white listed data stored in nda.conf.

For first time scan it is reccomended to only configure 'TARGET' in
config. This way, all data you require may for white listing devices
will be displayed for you. 
