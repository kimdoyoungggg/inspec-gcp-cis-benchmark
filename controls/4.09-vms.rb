# Copyright 2019 The inspec-gcp-cis-benchmark Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

title 'Ensure that Compute instances do not have public IP addresses'

  gcp_project_id = input('gcp_project_id')
  gce_zones = input('gce_zones')
  cis_version = input('cis_version')
  cis_url = input('cis_url')
  control_id = '4.9'
  control_abbrev = 'vms'
  
  gce_instances = GCECache(project: gcp_project_id, gce_zones: gce_zones).gce_instances_cache
  
  control "cis-gcp-#{control_id}-#{control_abbrev}" do
    impact 'medium'
  
    title "[#{control_abbrev.upcase}] Ensure that Compute instances do not have public IP addresses'"
  
    desc 'Compute instances should not be configured to have external IP addresses.'
    desc 'rationale', "To reduce your attack surface, Compute instances should not have public IP addresses. Instead, instances should be configured behind load balancers, to minimize the instance's exposure to the internet."
  
    tag cis_scored: true
    tag cis_level: 2
    tag cis_gcp: control_id.to_s
    tag cis_version: cis_version.to_s
    tag project: gcp_project_id.to_s
    tag nist: ['SC-1']
  
    ref 'CIS Benchmark', url: cis_url.to_s
    ref 'GCP Docs', url: 'https://cloud.google.com/load-balancing/docs/backend- service#backends_and_external_ip_addresses'
    ref 'GCP Docs', url: 'https://cloud.google.com/compute/docs/instances/connecting- advanced#sshbetweeninstances'
    ref 'GCP Docs', url: 'https://cloud.google.com/compute/docs/instances/connecting-to-instance'
    ref 'GCP Docs', url: 'https://cloud.google.com/compute/docs/ip-addresses/reserve-static-external-ip-
  address#unassign_ip'
    ref 'GCP Docs', url:'https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-
    constraints'
  
    gce_instances.each do |instance|
      instance_object = google_compute_instance(project: gcp_project_id, zone: instance[:zone], name: instance[:name])
      describe "[#{gcp_project_id}] Instance #{instance[:zone]}/#{instance[:name]}" do
      if instance_object.network_interfaces.access_configs.nat_ip.nil?
        it 'Instance does not have PublicIP'
      end
    end
  end
  