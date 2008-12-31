#!/usr/bin/perl

use strict;
use warnings;
use Getopt::Long;

use Net::BGP;
use Net::BGP::Process;

my $help = <<EOF;

bgp_simple.pl: Simple BGP peering and prefix injection script.

usage:
bgp_simple.pl: 
	       	-myas   ASNUMBER		# (mandatory) our AS number
	       	-myip   IP address		# (mandatory) our IP address to source the sesion from
	     	-peerip IP address		# (mandatory) peer IP address
		-peeras	ASNUMBER		# (mandatory) peer AS number
 		[-v]                       	# (optional) provide verbose output to STDOUT, use twice to get debugs
 		[-p file]                       # (optional) prefixes to advertise (bgpdump formatted)
		[-o file]			# (optional) write all sent and received UPDATE messages to file
                [-m number]                     # (optional) maximum number of prefixes to advertise
                [-n IP address]                 # (optional) next hop self, overrides original value
                [-dry]                 		# (optional) dry run; dont build adjacency, but check prefix file (requires -p)
                [-f KEY=REGEX]                 	# (optional) filter on input prefixes (requires -p), repeat for multiple filters
							KEY is one of the following attributes (CaSE insensitive):

						 	NEIG		originating neighbor
							NLRI		NLRI/prefix(es)
 							ASPT		AS_PATH
							ORIG		ORIGIN
							NXHP		NEXT_HOP
							LOCP		LOCAL_PREF
							MED		MULTI_EXIT_DISC
							COMM		COMMUNITY
							ATOM		ATOMIC_AGGREGATE
							AGG		AGGREGATOR

							REGEX is a perl regular expression to be expected in a 
							match statement (m/REGEX/)

Without any prefix file to import, only an adjacency is established and the advertised NLRIs,
including their attributes, are logged.

EOF

my %BGP_ERROR_CODES = (
			1 => { 		__NAME__ => "Message Header Error", 
					0 => "unknown",
				 	1 => "Connection Not Synchronized", 
					2 => "Bad Message Length", 
					3 => "Bad Message Type",
			},
			2 => {		__NAME__ => "OPEN Message Error",
					0 => "unknown",
					1 => "Unsupported Version Number",
					2 => "Bad Peer AS",
					3 => "Bad BGP Identifier",
					4 => "Unsupported Optional Parameter",
					5 => "[Deprecated], see RFC4271",
					6 => "Unacceptable Hold Time",
			},
			3 => { 		__NAME__ => "UPDATE Message Error",
					0 => "unknown",
					1 => "Malformed Attribute List",
					2 => "Unrecognized Well-known Attribute",
					3 => "Missing Well-known Attribute",
					4 => "Attribute Flags Error",
					5 => "Attribute Length Error",
					6 => "Invalid ORIGIN Attribute",
					7 => "[Deprecated], see RFC4271",
					8 => "Invalid NEXT_HOP Attribute",
					9 => "Optional Attribute Error",
					10 => "Invalid Network Field",
					11 => "Malformed AS_PATH",
			},
			4 => {		__NAME__ => "Hold Timer Expired",
					0 => "unknown",
			},
			5 => {		__NAME__ => "Finite State Machine Error",
					0 => "unknown",
			},
			6 => {		__NAME__ => "Cease",
					0 => "unknown",
					1 => "Maximum Number of Prefixes Reached",
					2 => "Administrative Shutdown",
					3 => "Peer De-configured",
					4 => "Administrative Reset",
					5 => "Connection Rejected",
					6 => "Other Configuration Change",
					7 => "Connection Collision Resolution",
					9 => "Out of Resources",
			},
);

my $infile;
my $outfile;
my $prefix_limit;
my $verbose = 0;
my $dry;
my $next_hop_self = "0";
my $adj_next_hop = 0;
my $local_pref=500;
my $myas;
my $myip;
my $peeras;
my $peerip;
my %regex_filter;

GetOptions( 	'help' 		=> sub{ sub_debug("m","$help"); exit; },   
		'm=s' 		=> \$prefix_limit,
		'v+' 		=> \$verbose,
		'dry' 		=> \$dry,
		'n:s' 		=> \$next_hop_self,
		'p=s' 		=> \$infile,
		'f=s' 		=> \%regex_filter,
		'o=s' 		=> \$outfile,
		'myas=s' 	=> \$myas,
		'myip=s' 	=> \$myip,
		'peeras=s' 	=> \$peeras,
		'peerip=s' 	=> \$peerip );

	
die "\nPlease provide -myas, -myip, -peerip and -peeras!\n$help" unless ($myas && $myip && $peeras && $peerip);

die "Peer IP address is not valid: $peerip" 	if (sub_checkip($peerip));
die "Peer AS number is not valid: $peeras"   	if (sub_checkas($peeras));
die "Our IP address is not valid: $myip"   	if (sub_checkip($myip));
die "Our AS number is not valid: $myas"   	if (sub_checkas($myas));

my $peer_type = ( $myas == $peeras ) ? "iBGP" : "eBGP";

if ($next_hop_self ne "0") 
{
	if ($peer_type eq "eBGP")
	{
		sub_debug ("i","Force to change next hop ignored due to eBGP session (next hop self implied here).\n");
		$adj_next_hop = 1;
		$next_hop_self = "$myip";
	} elsif ($peer_type eq "iBGP") 
	{
		if ($next_hop_self eq "")
		{
			$adj_next_hop = 1;
			$next_hop_self = "$myip";
		} else 
		{
			die "Next hop self IP address is not valid: $next_hop_self" if sub_checkip($next_hop_self);
			$adj_next_hop = 1;
		}
	}
} else 
{
	$adj_next_hop = 0;
	$next_hop_self = "$myip";
};
		
die "Cannot open file $infile" 	if ( ($infile) && !( open (INPUT, $infile) ) ); 
close (INPUT);
die "Cannot open file $outfile" if ( ($outfile) && !( open (OUTPUT,">$outfile") ) ); 
close (OUTPUT);

die "Filter on input file actually requires an input file (-p)" if ( !($infile) && (%regex_filter) );
if (%regex_filter)
{
	foreach my $key (keys %regex_filter)
	{
		die "Key " . uc($key) . " is not valid.\n" 		unless (uc($key) =~ /NEIG|NLRI|ASPT|ORIG|NXHP|LOCP|MED|COMM|ATOM|AGG/); 
		die "Regex" . $regex_filter{$key} . " is bogus.\n" 	unless ( eval { qr/$regex_filter{$key}/ } );
	}
}

sub_debug ("m", "---------------------------------------- CONFIG SUMMARY --------------------------------------------------\n");
sub_debug ("m", "Configured for an $peer_type session between me (ASN$myas, $myip) and peer (ASN$peeras, $peerip).\n");
sub_debug ("m", "Generating verbose output, level $verbose.\n") 					if $verbose;
sub_debug ("m", "Will use prefixes from file $infile.\n") 					if $infile;
sub_debug ("m", "Will write sent and received UPDATEs to file $outfile.\n") 			if $outfile;
sub_debug ("m", "Maximum number of prefixes to be advertised: $prefix_limit.\n") 		if ($prefix_limit);
sub_debug ("m", "Will spoof next hop address to $next_hop_self.\n") 				if (($adj_next_hop) && ($peer_type eq "iBGP"));
sub_debug ("m", "Will set next hop address to $next_hop_self because of eBGP peering.\n") 	if ($peer_type eq "eBGP");
if (%regex_filter)
{
	sub_debug ("m", "Will apply filter to input file:\n");
	foreach my $key (sort keys %regex_filter)
	{
		sub_debug ("m", "\t" . uc($key) . " =~ /" .  $regex_filter{$key} . "/\n");
	}
} 
sub_debug ("m", "----------------------------------------------------------------------------------------------------------\n");

if ($dry)
{
	die "Prefix file (-f) required for dry run!\n" if not ($infile);
	sub_debug ("m", "Starting dry run.\n");
	sub_update_from_file();
	sub_debug ("m", "Dry run done, exiting.\n");
	exit;
}

my $bgp  = Net::BGP::Process->new();
my $peer = Net::BGP::Peer->new(
        Start    		=> 0,
        ThisID   		=> $myip,
        ThisAS   		=> $myas,
        PeerID   		=> $peerip,
        PeerAS   		=> $peeras,
        KeepaliveCallback    	=> \&sub_keepalive_callback,
        UpdateCallback       	=> \&sub_update_callback,
        NotificationCallback 	=> \&sub_notification_callback,
        ErrorCallback        	=> \&sub_error_callback,
        OpenCallback        	=> \&sub_open_callback,
        ResetCallback        	=> \&sub_reset_callback,
);

# full update required
my $full_update = 0;

sub_debug ("i","Trying to establish session...\n"); 
$bgp->add_peer($peer);
$peer->add_timer(\&sub_timer_callback, 10);
$bgp->event_loop();

sub sub_debug
{
	my $level = shift(@_);	
	my $msg   = shift(@_);	

	print $msg if ($level eq "m");				# mandatory
	print $msg if ($level eq "e");				# error
	print $msg if ( ($level eq "i") && ($verbose >= 1) );	# informational
	print $msg if ( ($level eq "u") && ($verbose >= 1) );	# UPDATE
	print $msg if ( ($level eq "d") && ($verbose >= 2) );	# debug

	
	if ( ($outfile) && ($level eq "u") )
	{
		open (OUTPUT,">>$outfile") || die "Cannot open file $outfile"; 
		print OUTPUT "$msg";	
		close (OUTPUT);
	}
}

sub sub_checkip
{
	("@_" !~ /^([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])$/) 
	? 1 : 0;

}

sub sub_checkas
{
	("@_" !~ /^([1-9]\d?\d?\d?|[1-5]\d\d\d\d|6[0-4]\d\d\d|65[0-4]\d\d|655[0-2]\d|6553[0-5])$/) ? 1 : 0;
}

sub sub_checkaspath
{
	# ("@_" !~ /^(([1-9]\d?\d?\d?|[1-5]\d\d\d\d|6[0-4]\d\d\d|65[0-4]\d\d|655[0-2]\d|6553[0-5]))( ([1-9]\d?\d?\d?|[1-5]\d\d\d\d|6[0-4]\d\d\d|65[0-4]\d\d|655[0-2]\d|6553[0-5]))*$|^$/) ? 1 : 0;
	("@_" !~ /^(([1-9]\d?\d?\d?|[1-5]\d\d\d\d|6[0-4]\d\d\d|65[0-4]\d\d|655[0-2]\d|6553[0-5]))(((\s| \{|,)([1-9]\d?\d?\d?|[1-5]\d\d\d\d|6[0-4]\d\d\d|65[0-4]\d\d|655[0-2]\d|6553[0-5]))\}?)*$|^$/) ? 1 : 0;
}


sub sub_checkcommunity
{
	("@_" !~ /^(([1-9]\d?\d?\d?|[1-5]\d\d\d\d|6[0-4]\d\d\d|65[0-4]\d\d|655[0-2]\d|6553[0-5])\:([1-9]\d?\d?\d?|[1-5]\d\d\d\d|6[0-4]\d\d\d|65[0-4]\d\d|655[0-2]\d|6553[0-5]))( (([1-9]\d?\d?\d?|[1-5]\d\d\d\d|6[0-4]\d\d\d|65[0-4]\d\d|655[0-2]\d|6553[0-5])\:([1-9]\d?\d?\d?|[1-5]\d\d\d\d|6[0-4]\d\d\d|65[0-4]\d\d|655[0-2]\d|6553[0-5])))*$|^$/) ? 1 : 0;
}

sub sub_checkprefix
{
	("@_" !~ /^(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\/(\d|[12]\d|3[0-2])\s?)+$/) 
	? 1 : 0;

}

sub sub_connect_peer
{
	my ($peer) = shift(@_);
    	my $peerid =  $peer->peer_id();
        my $peeras =  $peer->peer_as();

	sub_debug ("i","Trying to establish session...\n"); 

	$bgp->remove_peer($peer);
	$bgp->add_peer($peer);

	$full_update = 0;
}

sub sub_timer_callback
{
        my ($peer) = shift(@_);
        my $peerid =  $peer->peer_id();
        my $peeras =  $peer->peer_as();

	sub_debug ("d", "Loop triggered\n");

	if (! $peer->is_established)
	{ 
		sub_connect_peer($peer); 

	} elsif (($infile) && (! $full_update))
	{ 	
		sub_debug ("m","Sending full update.\n");

		$full_update = 1;
		sub_update_from_file($peer);

		sub_debug ("m", "Full update sent.\n");

	}
}

sub sub_open_callback
{
        my ($peer) = shift(@_);
        my $peerid =  $peer->peer_id();
        my $peeras =  $peer->peer_as();
        sub_debug ("i","Connection established with peer $peerid, AS $peeras.\n");
	$full_update = 0;
}

sub sub_reset_callback
{
        my ($peer) = shift(@_);
        my $peerid =  $peer->peer_id();
        my $peeras =  $peer->peer_as();
        sub_debug ("e","Connection reset with peer $peerid, AS $peeras.\n");
	
}

sub sub_keepalive_callback
{
	my ($peer) = shift(@_);
	my $peerid =  $peer->peer_id();
	my $peeras =  $peer->peer_as();
	sub_debug ("d","Keepalive received from peer $peerid, AS $peeras.\n");

}

sub sub_update_callback
{
	my ($peer) = shift(@_);
	my ($update) = shift(@_);
	my $peerid =  $peer->peer_id();
	my $peeras =  $peer->peer_as();
	my $nlri_ref = $update->nlri();
	my $locpref = $update->local_pref();
	my $med = $update->med();
	my $aspath = $update->as_path();
	my $comm_ref = $update->communities();
	my $origin = $update->origin();
	my $nexthop = $update->next_hop();
	my $aggregate = $update->aggregator();

	sub_debug ("u","Update received from PEER [$peerid], ASN [$peeras]: ");

	my @prefixes = @$nlri_ref;
	sub_debug ("u","PREFIXES [@prefixes] ");

	sub_debug ("u", "AS_PATH [$aspath] ");
	sub_debug ("u", "LOCAL_PREF [$locpref] ") 	if ($locpref);
	sub_debug ("u", "MED [$med] ")			if ($med);
	sub_debug ("u", "COMMUNITY ");

	my @communities = @$comm_ref;
	sub_debug ("u", "[@communities] " );
	
	sub_debug ("u", "ORIGIN [IGP] ") if ($origin eq "0");
	sub_debug ("u", "ORIGIN [EGP] ") if ($origin eq "1");
	sub_debug ("u", "ORIGIN [INCOMPLETE] ") if ($origin eq "2");

	my @aggregator = @$aggregate;
	sub_debug ("u", "AGGREGATOR [@aggregator] ");

	sub_debug ("u", "NEXT_HOP [$nexthop]\n");
}

sub sub_notification_callback
{
	my ($peer) = shift(@_);
	my ($msg) = shift(@_);

       	my $peerid =  $peer->peer_id();
        my $peeras =  $peer->peer_as();
	my $error_code = $msg->error_code();
	my $error_subcode = $msg->error_subcode();
	my $error_data = $msg->error_data();

	my $error_msg = $BGP_ERROR_CODES{ $error_code }{ __NAME__ };
	sub_debug ("e", "NOTIFICATION received: TYPE [$error_msg]");
	sub_debug ("e", " SUBCODE [" . $BGP_ERROR_CODES{ $error_code }{ $error_subcode } . "]") 	if ($error_subcode);
	sub_debug ("e", " ADDITIONAL_PEER_DATA [" .  unpack ("H*", $error_data) . "]") 		if ($error_data);
	sub_debug ("e", "\n");

}

sub sub_error_callback
{
	my ($peer) = shift(@_);
	my ($msg) = shift(@_);

       	my $peerid =  $peer->peer_id();
        my $peeras =  $peer->peer_as();
	my $error_code = $msg->error_code();
	my $error_subcode = $msg->error_subcode();
	my $error_data = $msg->error_data();

	my $error_msg = $BGP_ERROR_CODES{ $error_code }{ __NAME__ };
	sub_debug ("e", "ERROR occured: TYPE [$error_msg]");
	sub_debug ("e", " SUBCODE [" . $BGP_ERROR_CODES{ $error_code }{ $error_subcode } . "]") 	if ($error_subcode);
	sub_debug ("e", " DATA [" .  unpack ("H*", $error_data) . "]") 				if ($error_data);
	sub_debug ("e", "\n");
}

sub sub_update_from_file
{

	my ($peer) = shift(@_);
	open (INPUT, $infile) || die "Could not open $infile\n";
	my $cur = 1;

	while (<INPUT>)
	{
		my $line = $_;
		chomp($line);
			
		my @nlri = split /\|/,$line; 

		# Filter based on advertising neighbor?
		if (($regex_filter{"NEIG"}) && ($nlri[3] !~ qr/$regex_filter{"NEIG"}/) )
		{
			sub_debug ("e", "Line [$.], Neighbor [$nlri[3]] skipped due to NEIG filter.\n");
			next;
		};

		# Prefix valid?
		if (sub_checkprefix($nlri[5]))
		{
			sub_debug ("e", "Prefix [ $nlri[5] ] failed because of wrong prefix format.\n");
			next;
		}; 
		# Filter based on prefix?
		if (($regex_filter{"NLRI"}) && ($nlri[5] !~ qr/$regex_filter{"NLRI"}/) )
		{
			sub_debug ("e", "Line [$.], Prefix [$nlri[5]] skipped due to NLRI filter.\n");
			next;
		};

		my $prefix = $nlri[5];

		if (sub_checkaspath($nlri[6])) { my_debug ("e", "Prefix [ $prefix ] failed because of wrong AS_PATH format.\n"); next; };
		my $aspath = Net::BGP::ASPath->new($nlri[6]);
 		
		# add own AS for eBGP adjacencies
#                $aspath += "$myas" if ($peer_type eq "eBGP");

		if (sub_checkcommunity($nlri[11])) { my_debug ("e", "Prefix [ $prefix ] failed because of wrong COMMUNITY format.\n"); next; };
		my @communities = split / /,$nlri[11]; 

		my $med = $nlri[10] if !(($nlri[10] eq "0") || ($nlri[10] eq ""));

		if (sub_checkip($nlri[8])) { my_debug ("e", "Prefix [ $prefix ] failed because of wrong NEXT_HOP format.\n"); next; }; 
		my $nexthop = $nlri[8];

             	# force NEXT_HOP change for eBGP sessions, or if requested for iBGP sessions
                $nexthop = $next_hop_self if ( ($peer_type eq "eBGP") || ($peer_type eq "iBGP") && ($adj_next_hop) );

		my $origin = 2;
		$origin = 0 if ($nlri[7] eq "IGP");
		$origin = 1 if ($nlri[7] eq "EGP");
		$origin = 2 if ($nlri[7] eq "INCOMPLETE");

		my @agg;
		@agg =  split / /,$nlri[13] if ( $nlri[13] ne "");

		my $atomic_agg = ($nlri[12] eq "AG") ? 1 : 0; 

		sub_debug ("u", "Send UPDATE: ") 			if (!$dry);
		sub_debug ("u", "Generated UPDATE (not sent): ") 	if ($dry);
		sub_debug ("u", "PREFIX [$prefix] AS_PATH [$aspath] ");
		sub_debug ("u", "AGGREGATOR [@agg] ")			if (@agg);
		sub_debug ("u", "ATOMIC_AGGREGATE [$atomic_agg] ");
		sub_debug ("u", "LOCAL_PREF [$local_pref] ") 		if ($peer_type eq "iBGP");
		sub_debug ("u", "MED [$med] ")				if ($med);
		sub_debug ("u", "COMMUNITIY [@communities] ");
		sub_debug ("u", "ORIGIN [$nlri[7]] NEXT_HOP [$nexthop]\n");

		if (! $dry)
		{
			my $update = Net::BGP::Update->new(
       				NLRI            => [ $prefix ],
       				AsPath          => $aspath,
       				NextHop         => $nexthop,
				Origin		=> $origin,
			);
			$update->communities([ @communities ])	if (@communities);
			$update->aggregator([ @agg ])		if (@agg);
			$update->atomic_aggregate("1") 		if ($atomic_agg);
			$update->med($med)			if ($med);
			$update->local_pref($local_pref) 	if ($peer_type eq "iBGP");
			
			$peer->update($update);
		}
		$cur += 1;
		last if (($prefix_limit) && ($cur > $prefix_limit));
	}	
	close (INPUT);
}
