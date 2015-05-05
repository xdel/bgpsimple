# simple BGP peering and route injection script #

This perl script allows to setup an BGP adjacency with a BGP peer, monitor the messages and updates received from that peer, and to send out updates from a predefined set of NLRIs/attributes. BGP session and message handling is done by Net::BGP.

The script was mainly written to take a file with BGP route information (TABLE\_DUMP\_V2 format) and to inject these routes over a BGP adjacency. It grew a little over the time, and has some additional features to tweak and filter those routes before advertising them to the peer.

UPDATE messages received will be logged. Currently, there is no implementation of any local routing policy (except the features and sanity checks described at the NOTES section of the README). Furthermore, no adj-rib-in and adj-rib-out databases are maintained.

The latest version can be obtained [here](http://bgpsimple.googlecode.com/svn/trunk/bgp_simple.pl). Please see [the Wiki](http://code.google.com/p/bgpsimple/wiki/README) for more information.