use IO::Socket;
my $s = IO::Socket::INET->new(
    Proto => "tcp",
    PeerAddr => "127.0.0.1",
    PeerPort => 22,
    Timeout => 3);
die "Could not connect to host 127.0.0.1 port 22" unless $s;
print $s "testing state machine transitions";
close $s;
