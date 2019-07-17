use warnings;
use strict;

use Carp qw(confess);
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

    my $domain_name = '';
    $domain_name = " ".$domain->name if $domain;
    like($@,qr'unknown',$vm->type.$domain_name) or exit;

    $domain->remove(user_admin) if $domain;
}

sub test_spice($vm) {
    my $domain = create_domain(vm => $vm, screen => 'spice', active => 1);

    if ($vm->type =~ /KVM/) {
        my $doc = XML::LibXML->load_xml( string => $domain->xml_description());
        my @graph = $doc->findnodes('/domain/devices/graphics');

        is(scalar @graph, 1);
        is($graph[0]->getAttribute('type'), 'spice') if $graph[0];
    }

    my $display_spice = $domain->display_file(user_admin,'spice');
    ok($display_spice);

    my $display_x2go;
    eval { $display_x2go = $domain->display_file(user_admin,'x2go') };
    like($@,qr/exposed port/i);
    is($display_x2go,undef);

    like($domain->display(user_admin),qr(^spice://), $domain->name) or exit;

    my $domain_f = Ravada::Front::Domain->open($domain->id);
    like($domain_f->display(user_admin),qr(^spice://));

    my $display_info = $domain_f->display_info(user_admin);
    like($display_info->{display},qr{^spice://});

    is($domain_f->_screen_type, 'spice');
    my $display_file0 = $domain_f->display_file(user_admin);
    my $display_file1 = $domain_f->display_file(user_admin,'spice');
    is($display_file0, $display_file1, $vm->type." ".$domain->name);

    like($display_file0,qr(type=spice)m);
    like($display_file0,qr(port=\d)m);

    if ($vm->type ne 'Void') {
        SKIP: {
            if (!$display_info->{tls_port}) {
                my $msg = "No TLS configuration found, skipped";
                diag($msg);
                skip($msg,1);
            }
            my $display_tls = $domain_f->display_file(user_admin,'spice-tls');
            ok($display_tls);
        }
    }
    $domain->remove(user_admin);
}

sub test_x2go($vm) {
    my $domain = create_domain(vm => $vm, screen => 'x2go');
    if ($domain->type eq 'KVM') {
        my $doc = XML::LibXML->load_xml( string => $domain->xml_description());
        my @graph = $doc->findnodes('/domain/devices/graphics');

        is(scalar @graph, 0);
    }
    my $display_info0;
    eval { $display_info0 = $domain->display_info(user_admin,'spice')};
    like($@,qr(I can't find graphics), $vm->type);
    ok(!$display_info0) or confess(Dumper($display_info0));

    my $display_spice;
    eval { $display_spice = $domain->display_file(user_admin,'spice') };
    like($@,qr/I can't find graphics/,$vm->type." ".$domain->name);
    ok(!$display_spice,$domain->type." ".$domain->name) or exit;

    my $display_x2go;
    eval { $display_x2go = $domain->display_file(user_admin,'x2go') };
    is($@,'');
    like($display_x2go,qr/port=\d+/m);

    like($domain->display(user_admin),qr(^x2go://));

    my $domain_f = Ravada::Front::Domain->open($domain->id);
    like($domain_f->display(user_admin),qr(^x2go://));

    my $display_info = $domain_f->display_info(user_admin);
    like($display_info->{display},qr{^x2go://});

    is($domain_f->_screen_type, 'x2go');
    my $display_file0 = $domain_f->display_file(user_admin);
    my $display_file1 = $domain_f->display_file(user_admin,'x2go');
    is($display_file0, $display_file1, $vm->type." ".$domain->name);

    like($display_file0,qr(sshport=\d+)m);

    $domain->remove(user_admin);
}

sub test_x2go_spice($vm) {
    my $domain = create_domain(vm => $vm, screen => ['spice','x2go'] , active => 1);

    if ($domain->type eq 'KVM') {
        my $doc = XML::LibXML->load_xml( string => $domain->xml_description());
        my @graph = $doc->findnodes('/domain/devices/graphics');

        is(scalar @graph, 1);
        is($graph[0]->getAttribute('type'), 'spice') if $graph[0];
    }

    my @screen = $domain->get_controller('screen');
    is(scalar@screen,2);

    my $display_spice = $domain->display_file(user_admin,'spice');
    ok($display_spice);

    my $display_x2go = $domain->display_file(user_admin,'x2go');
    ok($display_x2go);

    like($domain->display(user_admin),qr(^spice://));

    $domain->start(user_admin);
    rvd_back->_process_requests_dont_fork(1);

    my $domain_f = Ravada::Front::Domain->open($domain->id);
    like($domain_f->display(user_admin),qr(^spice://));

    my $display_info = $domain_f->display_info(user_admin);
    like($display_info->{display},qr{^spice://});

    my $info = $domain->info(user_admin);
    my $screen = $info->{hardware}->{screen};
    is (scalar(@$screen), 2);
    is($screen->[0]->{type}, 'spice');
    is($screen->[1]->{type}, 'x2go');

    like($screen->[0]->{port}, qr'\d+$', $domain->name) or die Dumper($screen);
    like($screen->[1]->{public_port}, qr'^\d+$');

    like($screen->[0]->{display}, qr'^spice://', $domain->name) or exit;
    like($screen->[1]->{display}, qr'^x2go://');

    my $display_file_spice = $domain_f->display_file(user_admin,'spice');
    like($display_file_spice,qr(type=spice)m);
    like($display_file_spice,qr(port=\d)m);

    my $display_file_x2go = $domain_f->display_file(user_admin,'x2go');
    like($display_file_x2go,qr(port=\d)m);

    $domain->remove(user_admin);
}

sub test_drivers($vm) {
    my $domain = create_domain(vm => $vm, screen => ['spice','x2go'] , active => 0);

    ok(scalar $domain->drivers('screen')) or exit;

}

########################################################################

for my $vm_name ( vm_names() ) {
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

        test_drivers($vm);

        test_x2go_spice($vm);
        test_unknown($vm);
        test_spice($vm);
        test_x2go($vm);

    }
}

clean( );

done_testing();
