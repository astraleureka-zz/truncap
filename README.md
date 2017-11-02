# truncap
a packet capture tool for obtaining only TCP/IP headers (no data payload)

tcpdump can capture with a limited snap size but dumps may contain fragments of data
which can be problematic for some use cases. truncap fills this gap in functionality
by analyzing the traffic and capturing only the variable size headers, leaving the
rest of the payload unsaved.

truncap will rewrite the packet checksums in order for the new payload-free packet
to pass validation, however all other important header fields are left untouched
and contain the original information obtained in the capture. the checksum update
silences some tools that complain about potentially "damaged" captures with partial
payloads.

