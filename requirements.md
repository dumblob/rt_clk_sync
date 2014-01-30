accurate
*   OS name + version
*   pcap version
*   NTP version (present in the packet header) + configuration
*   HW eth card
    *   type + vendor
    *   driver name + version
*   the whole NTP packet
*   system time [gettimeofday()] when the frame was captured (i.e. ASAP)
*   system time each second (independent from the packet capturing - e.g. in second thread)

4 long-time measurements (at least 25 hours) with exactly 1 3 5 and maybe 10 stratum_servers/boundary_clock
*   with current NTP
*   with PTP|NTP utilizing the new compositing filter
