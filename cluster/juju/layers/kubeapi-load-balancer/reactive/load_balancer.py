#!/usr/bin/env python

# Copyright 2015 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import socket
import subprocess

from charms import layer
from charms.reactive import when, when_any, when_not
from charms.reactive import set_state, remove_state
from charms.reactive.helpers import data_changed
from charmhelpers.core import hookenv
from charmhelpers.contrib.charmsupport import nrpe

from charms.layer import haproxy


PEM_PATH = '/etc/haproxy/haproxy.pem'
TEMPLATE = 'kube-api-load-balancer.cfg'


@when('certificates.available')
def request_server_certificates(tls):
    """Send the data that is required to create a server certificate for
    this server."""
    # Use the public ip of this unit as the Common Name for the certificate.
    common_name = hookenv.unit_public_ip()
    # Create SANs that the tls layer will add to the server cert.
    sans = [
        hookenv.unit_public_ip(),
        hookenv.unit_private_ip(),
        socket.gethostname(),
    ]
    # Create a path safe name by removing path characters from the unit name.
    certificate_name = hookenv.local_unit().replace('/', '_')
    # Request a server cert with this information.
    tls.request_server_cert(common_name, sans, certificate_name)


@when('apiserver.available', 'certificates.server.cert.available')
def certificates_available(apiserver, tls):
    """The API server and the TLS (ca, key and cert) are available for this
    server, render the configuration file if the data has changed."""
    services = apiserver.services()
    # Get the tls paths from the layer data.
    layer_options = layer.options('tls-client')
    ca_path = layer_options.get('ca_certificate_path')
    cert_path = layer_options.get('server_certificate_path')
    cert_exists = cert_path and os.path.isfile(cert_path)
    key_path = layer_options.get('server_key_path')
    key_exists = key_path and os.path.isfile(key_path)
    # Do both the the key and certificate exist?
    if cert_exists and key_exists:
        # Create a PEM file that HAProxy can use.
        haproxy.create_pem(key_path, cert_path, ca_path, PEM_PATH)
        chown = ['chown', 'haproxy:haproxy', PEM_PATH]
        # Change the owner to haproxy so the process can read the file.
        subprocess.call(chown)
    else:
        hookenv.log('The key or cert does not exist.')
        hookenv.log('Check the server cert {}'.format(cert_path))
        hookenv.log('Check the server key {}'.format(key_path))

    pem_hash = ''
    if os.path.isfile(PEM_PATH):
        shasum = ['sha256sum', PEM_PATH]
        # Get the hash value of the PEM file.
        pem_hash = subprocess.check_output(shasum)
    pem_changed = data_changed('pem_hash', pem_hash)
    relation_changed = data_changed('apiserver', services)
    config_changed = data_changed('config', hookenv.config())
    # Only when the pem, relation or charm config changes render new config.
    if pem_changed or relation_changed or config_changed:
        hookenv.log('The relation or configuration data has changed.')
        unit_name = hookenv.local_unit().replace('/', '-')
        # Render the kube-api-load-balancer template.
        haproxy.configure(unit_name,
                          TEMPLATE,
                          services=services,
                          path_to_pem=PEM_PATH)


@when('website.available')
def provide_application_details(website):
    """Use the layer website relation to relay the hostname/port
    to any consuming kubernetes-workers, or other units that require the
    kubernetes API """
    website.configure(port=hookenv.config('port'))


@when('loadbalancer.available')
def provide_loadbalancing(loadbalancer):
    """Send the public address and port to the public-address interface, so
    the subordinates can get the public address of this loadbalancer."""
    loadbalancer.set_address_port(hookenv.unit_get('public-address'),
                                  hookenv.config('port'))


@when('nrpe-external-master.available')
@when_not('nrpe-external-master.initial-config')
def initial_nrpe_config(nagios=None):
    """Update the nagios configuration."""
    update_nrpe_config(nagios)
    set_state('nrpe-external-master.initial-config')


@when('nginx.available')
@when('nrpe-external-master.available')
@when_any('config.changed.nagios_context',
          'config.changed.nagios_servicegroups')
def update_nrpe_config(unused=None):
    """Get the hostnames and configure the checks for Nagios."""
    services = ('haproxy',)
    hostname = nrpe.get_nagios_hostname()
    current_unit = nrpe.get_nagios_unit_name()
    nrpe_setup = nrpe.NRPE(hostname=hostname)
    nrpe.add_init_service_checks(nrpe_setup, services, current_unit)
    nrpe_setup.write()


@when_not('nrpe-external-master.available')
@when('nrpe-external-master.initial-config')
def remove_nrpe_config(nagios=None):
    """Clean up the Nagios checks by removing the checks for the services."""
    remove_state('nrpe-external-master.initial-config')
    # List of systemd services for which the checks will be removed
    services = ('hproxy',)
    # The current nrpe-external-master interface doesn't handle a lot of logic,
    # use the charm-helpers code for now.
    hostname = nrpe.get_nagios_hostname()
    nrpe_setup = nrpe.NRPE(hostname=hostname)

    for service in services:
        nrpe_setup.remove_check(shortname=service)
