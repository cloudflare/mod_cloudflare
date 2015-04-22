package Cpanel::Easy::ModCloudflare;
our $easyconfig = {
    'version' => '$Rev: 1 $',
    'name'    => 'Mod CloudFlare',
    'note'    => 'Restore correct visitor IP addresses in log files and web applications',
    'url'     => 'https://www.cloudflare.com/resources-downloads#mod_cloudflare',
    'src_cd2' => 'mod_cloudflare',
    'hastargz' => 1,
    'step'    => {
        '0' => {
            'name'    => 'Compiling, installing, and activating',
            'command' => sub {
                my ($self) = @_;
                my ($rc, @msg) = $self->run_system_cmd_returnable( [ $self->_get_main_apxs_bin(), qw(-i -a -c mod_cloudflare.c)] );
                if (!$rc) { $self->print_alert_color('red', q{apxs mod_cloudflare.c failed}); }
                return ($rc, @msg);
            },            
        },
    },    
}; 
1;
