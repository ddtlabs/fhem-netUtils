# $Id$

package main;
sub NetUtils_Initialize() {}

package NetUtils;
  use Socket qw(inet_pton AF_INET6);
  
# ------------------------------------------------------------------------------
# Check that an IPv64 address (peer) is covered by an IPv64 address or range
# (allowed).
# IPv4 eg. 10.1.2.3 is included in 10.0.0.0/8 or 10.0.0.0/255.0.0.0)
# IPv6 eg. 2001:1a50:50a8:1:2:::5 is included in 2001:1a50:50a8:1::/64
# usage: isPeerAllowed(peer, allowed)
# - 'peer' has to be an IPv64 address
# - 'allowed' has to be an IPv64 address, an IPv64 range (dotted decimal/CIDR)
#   or a comma separated of these values
# ------------------------------------------------------------------------------
sub isPeerAllowed($$)
{
  my ($peer,$allowed) = @_;
  return $allowed if $allowed =~ m/^[01]$/;
  return 1 if $allowed =~ /^0.0.0.0\/0(.0.0.0)?$/; # not necessary but faster

  my $binPeer = ip2bin($peer);
  my @a = split(/,| /,$allowed);
  foreach (@a) {
#    next if !isIPv64Range($_);     # needed for ESPEasy combinedDevices Attribut, only
    my ($addr,$ip,$mask) = addrToCIDR($_);
    return 0 if !defined $ip || !defined $mask;   # return if ip or mask !guilty
    my $binAllowed = ip2bin($addr);
    my $binPeerCut = substr($binPeer,0,$mask);
    return 1 if ($binAllowed eq $binPeerCut);
  }

  return 0;
}


# ------------------------------------------------------------------------------
# Check whether 'peer' is a valid ip64 address, fqdn, hostname or not
# usage: isPeer(peer), where peer can be a comma or space separated list
# useful to check attr values
# ------------------------------------------------------------------------------
sub isPeerAddrValid($)
{
  my ($addr) = @_;
  return 0 if !defined $addr;
  my @ranges = split(/,| /,$addr);
  foreach (@ranges) {
    return 0 if !( isIPv64Range($_) || isFqdn($_) || isHostname($_) );
  }

  return 1;
}


# ------------------------------------------------------------------------------
# check if given ip or ip range is guilty 
# argument can be: 
# - ipv4, ipv4/CIDR, ipv4/dotted, ipv6, ipv6/CIDR
# - space or comma separated list of above.
# ------------------------------------------------------------------------------
sub isIPv64Range($)
{
  my ($addr) = @_;
  return 0 if !defined $addr;
  my @ranges = split(/,| /,$addr);
  foreach (@ranges) {
    my ($ip,$nm) = split("/",$_);
    if (isIPv4($ip)) {
      return 0 if defined $nm && !( isNmDotted($nm) || isNmCIDRv4($nm) );
    }
    elsif (isIPv6($ip)) {
      return 0 if defined $nm && !isNmCIDRv6($nm);
    }
    else {
      return 0;
    }
  }

  return 1;
}


# ------------------------------------------------------------------------------
# convert IPv64 address to binary format and return binary network part of 
# given address
# ------------------------------------------------------------------------------
sub ip2bin($)
{
  my ($addr) = @_;
  my ($ip,$mask) = split("/",$addr);
  my @bin;

  if (isIPv4($ip)) {
    $mask = 32 if !defined $mask;
    @bin = map substr(unpack("B32",pack("N",$_)),-8), split(/\./,$ip);
  }
  elsif (isIPv6($ip)) {
    $ip = expandIPv6($ip);
    $mask = 128 if !defined $mask;
    @bin = map {unpack('B*',pack('H*',$_))} split(/:/, $ip);
  }
  else {
    return undef;
  }

  my $bin = join('', @bin);
  my $binMask = substr($bin, 0, $mask);
 
  return $binMask; # return network part of $bin
}


# ------------------------------------------------------------------------------
# expand IPv6 address to 8 full blocks
# Advantage of IO::Socket: already installed and it seems to be the fastest way
# http://stackoverflow.com/questions/4800691/perl-ipv6-address-expansion-parsing
# ------------------------------------------------------------------------------
sub expandIPv6($)
{
  my ($ipv6) = @_;
#  use Socket qw(inet_pton AF_INET6);
  return join(":", unpack("H4H4H4H4H4H4H4H4",inet_pton(AF_INET6, $ipv6)));
}


# ------------------------------------------------------------------------------
# convert IPv64 address or range into CIDR notion
# return undef if addreess or netmask is not valid
# ------------------------------------------------------------------------------
sub addrToCIDR($)
{
  my ($addr) = @_;
  my ($ip,$mask) = split("/",$addr);
  # no nm specified
  return (isIPv4($ip) ? ("$ip/32",$ip,32) : ("$ip/128",$ip,128))
    if !defined $mask;
  # netmask is already in CIDR format and all values are valid
  return ("$ip/$mask",$ip,$mask) 
    if (isIPv4($ip) && isNmCIDRv4($mask)) || (isIPv6($ip) && isNmCIDRv6($mask));
  $mask = dottedNmToCIDR($mask);
  return (undef,undef,undef) if !defined $mask;

  return ("$ip/$mask",$ip,$mask);
}


# ------------------------------------------------------------------------------
# convert dotted decimal netmask to CIDR format
# return undef if nm is not in dotted decimal format
# ------------------------------------------------------------------------------
sub dottedNmToCIDR($) 
{
  my ($mask) = @_;
  return undef if !isNmDotted($mask);

  # dotted decimal to CIDR
  my ($byte1, $byte2, $byte3, $byte4) = split(/\./, $mask);
  my $num = ($byte1 * 16777216) + ($byte2 * 65536) + ($byte3 * 256) + $byte4;
  my $bin = unpack("B*", pack("N", $num));
  my $count = ($bin =~ tr/1/1/);

  return $count; # return number of netmask bits
}


# ------------------------------------------------------------------------------
sub isIPv4($) 
{
  return 0 if !defined $_[0];
  return 1 if $_[0] =~ m/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  return 0;
}

# ------------------------------------------------------------------------------
sub isIPv6($)
{
  return 0 if !defined $_[0];
  return 1 if $_[0] =~ m/^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;
  return 0;
}

# ------------------------------------------------------------------------------
sub isIPv64($)
{
  return 0 if !defined $_[0];
  return 1 if isIPv4($_[0]) || isIPv6($_[0]);
  return 0;
}
  
# ------------------------------------------------------------------------------
sub isNmDotted($)
{
  return 0 if !defined $_[0];
  return 1 if $_[0] =~ m/^(255|254|252|248|240|224|192|128|0)\.0\.0\.0|255\.(255|254|252|248|240|224|192|128|0)\.0\.0|255\.255\.(255|254|252|248|240|224|192|128|0)\.0|255\.255\.255\.(255|254|252|248|240|224|192|128|0)$/;
  return 0;
}

# ------------------------------------------------------------------------------
sub isNmDottedWildcard($)
{
  return 0 if !defined $_[0];
  return 1 if $_[0] =~ m/^0\.0\.0\.(255|127|63|31|15|7|3|1|0)|0\.0\.(255|127|63|31|15|7|3|1|0)\.255|0\.(255|127|63|31|15|7|3|1|0)\.255\.255|(255|127|63|31|15|7|3|1|0)\.255\.255\.255$/;
  return 0;
}

# ------------------------------------------------------------------------------
sub isNmCIDRv4($)
{
  return 0 if !defined $_[0];
  return 1 if $_[0] =~ m/^([0-2]?[0-9]|3[0-2])$/;
  return 0;
}

# ------------------------------------------------------------------------------
sub isNmCIDRv6($)
{
  return 0 if !defined $_[0];
  return 1 if $_[0] =~ m/^([0-9]?[0-9]|1([0-1][0-9]|2[0-8]))$/;
  return 0;
}

# ------------------------------------------------------------------------------
sub isFqdn($)
{
  return 0 if !defined $_[0];
  return 1 if $_[0] =~ m/^(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)$/;
  return 0;
}

# ------------------------------------------------------------------------------
sub isHostname($)
{
  return 0 if !defined $_[0];
  return 1 if ($_[0] =~ m/^([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$/) 
           && !(isIPv4($_[0]) || isIPv6($_[0]));
  return 0;
}

1;
