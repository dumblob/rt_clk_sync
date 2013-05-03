rt_clk_sync
===========

Hard Real-Time world-wide clock synchronization utilizing new better algorithms than PTP and NTP uses.

Objectives
----------

* "NTP without PLL" -- continue the ideas of [1], [2]
  * better stability (no feedback with obscured interoperation
    between digital quasi-VCO inside of OS which nobody
    understands, and the ad-hoc tuned PI-controller within ntpd in
    userspace
  * possibly better performance
    - provide means to tune system to particular process (computer
      clock) & measurement (network) noises by means of their
      absolute variances as well as temporal characteristics
    - according to control theory laws, optimally tuned estimator
      will perform same or better than any possible feedback system
      for the NTP task

* establish better NTP-like userspace program <-> OS interface
  * provide more clear i/f based on current time offset & drift
    estimates input into OS's timekeeping core;
    no P, I controller parameters, no ad-hoc quasi-VCOs;
    the Linux' adjtimex() is an example of devil's evil
  * try Linux as the reference implementation
  * join efforts with PTPd guys, they probably need exactly the
    same

* allow simultaneous locking to several NTP servers
  * AFAIK impossible with current ntpd client, correct me if wrong

* implement optimal linear estimator for clock processes, allowing
  to run with no absolute master at all [3], [4], [5]

In longer term:

* adaptive estimation of both clock and network parameters
  (autotuning, or continuous adaptation)

The ultimate goal (megalomanic):

* release the Internet-wide network of computers and their clocks,
  managed as a non-hierarhical cloud of clocks of very different
  stochastical properties (from GPSes and highly stable atomic
  standards to ordinary PC's crystals);
  apply clock ensembling algorithms to perform this large-scale
  time fusion

To Do
-----

### Outline ###

Test & prototype the idea in two different scenarios:
* LAN, 1 NTP server
* WAN, multiple NTP servers

### Tasks ###

* write clk_sync_observer, preferably in Linux' user-space
  * should run besides classical, non-patched ntpd
  * should monitor bidirectional NTP network datagrams, parse them
    and record their timestamps wrt. non-disciplined local clock
  * record evolution of disciplined ("ntp") time wrt. local clock
* provide means to perform/record simultaneous NTP queries to
  serveral NTP servers from fixed set

* define reference PC or "PC-like" HW platform
  * Ethernet card
  * some reasonable, but not unrealistically good local clock
    (i.e. no undeterministic, unbeatable errors, but on the other
    hand no unfairly good oscillators, common consumer/industrial
    HW only)
  * a means to output OS' clock synchronous marks, at least
    (at worst) using GPIO

* make a simple and portable FPGA & Rb clock reference measurement
  kit (for this purpose, 10ns is fairly good, so no fancy
  interpolation techniques from VZLU's TDC are needed)

* perform measurements
  * WAN scenario
  * LAN scenario

* evaluate acquired data
  * perform offline simulations of proposed algorithms
  * compare against bare NTP

* patch Linux' timekeeping.c
  * wipe out PI/quasi-VCO, replace with offset&drift estimates
    - for compatibility reason, current PI/VCO mess may perhaps
      become an upper shell on top of the offset/drift i/f

* write a NTP client-side userspace replacement, using algorithms
  and new OS i/f as described
  * first, only single-server mode
  * later, add multiple-servers fusion
  * (much later: adaptive filtering...)

People & Credits
----------------

* Dave Mills (for NTP)
* Thomas Gleixner (for current timekeeping.c)
* Pavel Pisa (guidance to tglx's timekeeping.c)
* Jan Pacner (ptpd port to QNX, started ntpd vs. ptpd comparisons)
* Marek Peca (noPLL NTP _idefix_, clock ensembling algorithms)

[1] J.Levine: Synchronizing computer clocks using Kalman filters.
    43rd PTTI Meeting, 2011.

[2] J.Ridoux, D.Veitch: Ten Microseconds Over LAN, for Free.
    IEEE ISPCS, 2007.

[3] K.R.Brown: The Theory of the GPS Composite Clock. Proceedings
    of ION GPS-91, 1991.

[4] C.A.Greenhall: A Review of Reduced Kalman Filters for Clock
    Ensembles. IEEE UFFC 2012.

[5] M.Peca, V.Michalek, M.Vacek: Clock Composition by Wiener
    Filtering Illustrated on Two Atomic Clocks. EFTF 2013
    (accepted)
