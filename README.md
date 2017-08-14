# udp-scan

This will do UDP port scans as a non-privileged user ie not root or a
program with SOCK_RAW capabilities.

It is currently very primitive. Additionally, it will report false
positives depending on how the host you are scanning is configured.

