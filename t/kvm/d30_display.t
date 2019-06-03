use warnings;
use strict;

use Data::Dumper;
use Test::More;

use lib 't/lib';
use Test::Ravada;

no warnings "experimental::signatures";
use feature qw(signatures);

clean( );

########################################################################

sub test_unknown($vm) {
    my $domain;
    eval { $domain = $vm->create_domain(name => new_domain_name
                    , id_owner => user_admin->id
                    , id_iso => search_id_iso('Alpine')
                    , active => 0
                    , memory => 256*1024
                    , disk => 1 * 1024 * 1024
                    , screen => 'unknown'
           );
    };

    like($@,qr'unknown');

    $domain->remove(user_admin) if $domain;
}

sub test_spice($vm) {
    my $domain = create_domain(vm => $vm, screen => 'spice', active => 1);
    my $doc = XML::LibXML->load_xml( string => $domain->xml_description());
    my @graph = $doc->findnodes('/domain/devices/graphics');

    is(scalar @graph, 1);
    is($graph[0]->getAttribute('type'), 'spice') if $graph[0];

    my $display_spice = $domain->display_file(user_admin,'spice');
    ok($display_spice);

    my $display_x2go = $domain->display_file(user_admin,'x2go');
    ok($display_x2go,'');

    $domain->remove(user_admin);
}

sub test_x2go($vm) {
    my $domain = create_domain(vm => $vm, screen => 'x2go');
    my $doc = XML::LibXML->load_xml( string => $domain->xml_description());
    my @graph = $doc->findnodes('/domain/devices/graphics');

    is(scalar @graph, 0);

    my $display_spice;
    eval { $display_spice = $domain->display_file(user_admin,'spice') };
    like($@,qr/I can't find graphics/);
    ok(!$display_spice);

    my $display_x2go;
    eval { $display_x2go = $domain->display_file(user_admin,'x2go') };
    like($@,qr'expose port');
    is($display_x2go,'');

    $domain->remove(user_admin);
}

sub test_x2go_spice($vm) {
    my $domain = create_domain(vm => $vm, screen => ['spice','x2go'] , active => 1);
    my $doc = XML::LibXML->load_xml( string => $domain->xml_description());
    my @graph = $doc->findnodes('/domain/devices/graphics');

    is(scalar @graph, 1);
    is($graph[0]->getAttribute('type'), 'spice') if $graph[0];

    my $display_spice = $domain->display_file(user_admin,'spice');
    ok($display_spice);

    my $display_x2go = $domain->display_file(user_admin,'spice');
    ok($display_x2go);

    $domain->remove(user_admin);
}


########################################################################

for my $vm_name ( 'KVM' ) {
  my $vm;

    eval { $vm = rvd_back->search_vm($vm_name) };

    SKIP: {
        my $msg = "SKIPPED test: No $vm_name VM found ";
        if ($vm && $vm_name =~ /kvm/i && $>) {
            $msg = "SKIPPED: Test must run as root";
            $vm = undef;
        }

        diag($msg)      if !$vm;
        skip $msg,10    if !$vm;

        test_unknown($vm);
        test_spice($vm);
        test_x2go($vm);
        test_x2go_spice($vm);
    }
}

clean( );

done_testing();
