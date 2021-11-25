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

title 'Ensure that Cloud SQL database Instances are secure'

gcp_project_id = input('gcp_project_id')
cis_version = input('cis_version')
cis_url = input('cis_url')
control_id = '6.2'
control_abbrev = 'db'

sql_cache = CloudSQLCache(project: gcp_project_id)

# 6.2.1
sub_control_id = "#{control_id}.1"
control "cis-gcp-#{sub_control_id}-#{control_abbrev}" do
  impact 'medium'

  title "[#{control_abbrev.upcase}] Ensure that the 'log_checkpoints' database flag for Cloud SQL PostgreSQL instance is set to 'on'"

  desc 'Enabling log_checkpoints causes checkpoints and restart points to be logged in the server log. Some statistics are included in the log messages, including the number of buffers written and the time spent writing them. '
  desc 'rationale', 'Enable system logging to include detailed information such as an event source, date,user, timestamp, source addresses, destination addresses, and other useful elements.'

  tag cis_scored: true
  tag cis_level: 1
  tag cis_gcp: sub_control_id.to_s
  tag cis_version: cis_version.to_s
  tag project: gcp_project_id.to_s
  tag nist: ['AU-3']

  ref 'CIS Benchmark', url: cis_url.to_s
  ref 'GCP Docs', url: 'https://cloud.google.com/sql/docs/postgres/flags#setting_a_database_flag'

  sql_cache.instance_names.each do |db|
    if sql_cache.instance_objects[db].database_version.include? 'POSTGRES'
      if sql_cache.instance_objects[db].settings.database_flags.nil?
        impact 'medium'
        describe "[#{gcp_project_id} , #{db} ] does not any have database flags." do
          subject { false }
          it { should be true }
        end
      else
        impact 'medium'
        describe.one do
          sql_cache.instance_objects[db].settings.database_flags.each do |flag|
            next unless flag.name == 'log_checkpoints'
            describe "[#{gcp_project_id} , #{db} ] should have a database flag 'log_checkpoints' set to 'on' " do
              subject { flag }
              its('name') { should cmp 'log_checkpoints' }
              its('value') { should cmp 'on' }
            end
          end
        end
      end
    else
      impact 'none'
      describe "[#{gcp_project_id}] [#{db}] is not a PostgreSQL database. This test is Not Applicable." do
        skip "[#{gcp_project_id}] [#{db}] is not a PostgreSQL database"
      end
    end
  end
end

# 6.2.2
sub_control_id = "#{control_id}.2"
control "cis-gcp-#{sub_control_id}-#{control_abbrev}" do
  impact 'medium'

  title "[#{control_abbrev.upcase}] Ensure 'log_error_verbosity' database flag for Cloud SQL PostgreSQL instance is set to 'DEFAULT' or stricter"

  desc 'The log_error_verbosity flag controls the verbosity/details of messages logged. '
  desc 'rationale', "Auditing helps in troubleshooting operational problems and also permits forensic analysis.
If log_error_verbosity is not set to the correct value, too many details or too few details
may be logged. This flag should be configured with a value of 'DEFAULT' or stricter. This
recommendation is applicable to PostgreSQL database instances."

  tag cis_scored: true
  tag cis_level: 1
  tag cis_gcp: sub_control_id.to_s
  tag cis_version: cis_version.to_s
  tag project: gcp_project_id.to_s
  tag nist: ['AU-3']

  ref 'CIS Benchmark', url: cis_url.to_s
  ref 'GCP Docs', url: 'https://cloud.google.com/sql/docs/postgres/flags'
  ref 'GCP Docs', url: 'https://www.postgresql.org/docs/current/runtime-config-logging.html#RUNTIME-CONFIG-LOGGING-WHAT'

  sql_cache.instance_names.each do |db|
    if sql_cache.instance_objects[db].database_version.include? 'POSTGRES'
      if sql_cache.instance_objects[db].settings.database_flags.nil?
        impact 'medium'
        describe "[#{gcp_project_id} , #{db} ] does not any have database flags." do
          subject { false }
          it { should be true }
        end
      else
        impact 'medium'
        describe.one do
          sql_cache.instance_objects[db].settings.database_flags.each do |flag|
            next unless flag.name == 'log_error_verbosity'
            describe "[#{gcp_project_id} , #{db} ] should have a database flag 'log_error_verbosity' set to 'DEFAULT' or stricter " do
              subject { flag }
              its('name') { should cmp 'log_error_verbosity' }
              its('value') { should cmp 'default' }
            end
            describe "[#{gcp_project_id} , #{db} ] should have a database flag 'log_error_verbosity' set to 'VERBOSE' or stricter " do
              subject { flag }
              its('name') { should cmp 'log_error_verbosity' }
              its('value') { should cmp 'verbose' }
            end
          end
        end
      end
    else
      impact 'none'
      describe "[#{gcp_project_id}] [#{db}] is not a PostgreSQL database. This test is Not Applicable." do
        skip "[#{gcp_project_id}] [#{db}] is not a PostgreSQL database"
      end
    end
  end
end

# 6.2.3
sub_control_id = "#{control_id}.3"
control "cis-gcp-#{sub_control_id}-#{control_abbrev}" do
  impact 'medium'

  title "[#{control_abbrev.upcase}] Ensure that the 'log_connections' database flag for Cloud SQL PostgreSQL instance is set to 'on'"

  desc 'Enabling the log_connections setting causes each attempted connection to the server to be logged, along with successful completion of client authentication. '
  desc 'rationale', "PostgreSQL does not log attempted connections by default. Enabling the log_connections setting will create log entries for each attempted connection
  as well as successful completion of client authentication which can be useful in troubleshooting issues and to determine any unusual connection attempts to the server."

  tag cis_scored: true
  tag cis_level: 1
  tag cis_gcp: sub_control_id.to_s
  tag cis_version: cis_version.to_s
  tag project: gcp_project_id.to_s
  tag nist: ['AU-3']

  ref 'CIS Benchmark', url: cis_url.to_s
  ref 'GCP Docs', url: 'https://cloud.google.com/sql/docs/postgres/flags#setting_a_database_flag'
  ref 'GCP Docs', url: 'https://www.postgresql.org/docs/9.6/runtime-config-logging.html#RUNTIME-CONFIG-LOGGING-WHAT'

  sql_cache.instance_names.each do |db|
    if sql_cache.instance_objects[db].database_version.include? 'POSTGRES'
      if sql_cache.instance_objects[db].settings.database_flags.nil?
        impact 'medium'
        describe "[#{gcp_project_id} , #{db} ] does not any have database flags." do
          subject { false }
          it { should be true }
        end
      else
        impact 'medium'
        describe.one do
          sql_cache.instance_objects[db].settings.database_flags.each do |flag|
            next unless flag.name == 'log_connections'
            describe "[#{gcp_project_id} , #{db} ] should have a database flag 'log_connections' set to 'on' " do
              subject { flag }
              its('name') { should cmp 'log_connections' }
              its('value') { should cmp 'on' }
            end
          end
        end
      end
    else
      impact 'none'
      describe "[#{gcp_project_id}] [#{db}] is not a PostgreSQL database. This test is Not Applicable." do
        skip "[#{gcp_project_id}] [#{db}] is not a PostgreSQL database"
      end
    end
  end
end

# 6.2.4
sub_control_id = "#{control_id}.4"
control "cis-gcp-#{sub_control_id}-#{control_abbrev}" do
  impact 'medium'

  title "[#{control_abbrev.upcase}] Ensure that the 'log_disconnections' database flag for Cloud SQL PostgreSQL instance is set to 'on'"

  desc 'Enabling the log_disconnections setting logs the end of each session, including the session duration.'
  desc 'rationale', "PostgreSQL does not log session details such as duration and session end by default. Enabling the log_disconnections
                    setting will create log entries at the end of each session which can be useful in troubleshooting issues and determine any unusual activity across a time period"

  tag cis_scored: true
  tag cis_level: 1
  tag cis_gcp: sub_control_id.to_s
  tag cis_version: cis_version.to_s
  tag project: gcp_project_id.to_s
  tag nist: ['AU-3']

  ref 'CIS Benchmark', url: cis_url.to_s
  ref 'GCP Docs', url: 'https://cloud.google.com/sql/docs/postgres/flags#setting_a_database_flag'
  ref 'GCP Docs', url: 'https://www.postgresql.org/docs/9.6/runtime-config-logging.html#RUNTIME-CONFIG-LOGGING-WHAT'

  sql_cache.instance_names.each do |db|
    if sql_cache.instance_objects[db].database_version.include? 'POSTGRES'
      if sql_cache.instance_objects[db].settings.database_flags.nil?
        impact 'medium'
        describe "[#{gcp_project_id} , #{db} ] does not any have database flags." do
          subject { false }
          it { should be true }
        end
      else
        impact 'medium'
        describe.one do
          sql_cache.instance_objects[db].settings.database_flags.each do |flag|
            next unless flag.name == 'log_disconnections'
            describe "[#{gcp_project_id} , #{db} ] should have a database flag 'log_disconnections' set to 'on' " do
              subject { flag }
              its('name') { should cmp 'log_disconnections' }
              its('value') { should cmp 'on' }
            end
          end
        end
      end
    else
      impact 'none'
      describe "[#{gcp_project_id}] [#{db}] is not a PostgreSQL database. This test is Not Applicable." do
        skip "[#{gcp_project_id}] [#{db}] is not a PostgreSQL database"
      end
    end
  end
end


# 6.2.5
sub_control_id = "#{control_id}.5"
control "cis-gcp-#{sub_control_id}-#{control_abbrev}" do
  impact 'medium'

  title "[#{control_abbrev.upcase}] Ensure 'log_duration' database flag for Cloud SQL PostgreSQL instance is set to 'on'"

  desc 'Enabling the log_duration setting causes the duration of each completed statement to be logged. '
  desc 'rationale', "Monitoring the time taken to execute the queries can be crucial in identifying any resource
  hogging queries and assessing the performance of the server. Further steps such as load
  balancing and use of optimized queries can be taken to ensure the performance and
  stability of the server. This recommendation is applicable to PostgreSQL database
  instances."

  tag cis_scored: true
  tag cis_level: 1
  tag cis_gcp: sub_control_id.to_s
  tag cis_version: cis_version.to_s
  tag project: gcp_project_id.to_s
  tag nist: ['AU-3']

  ref 'CIS Benchmark', url: cis_url.to_s
  ref 'GCP Docs', url: 'https://cloud.google.com/sql/docs/postgres/flags'
  ref 'GCP Docs', url: 'https://www.postgresql.org/docs/9.6/runtime-config-logging.html#GUC-LOG-MIN-DURATION-STATEMENT'

  sql_cache.instance_names.each do |db|
    if sql_cache.instance_objects[db].database_version.include? 'POSTGRES'
      if sql_cache.instance_objects[db].settings.database_flags.nil?
        impact 'medium'
        describe "[#{gcp_project_id} , #{db} ] does not any have database flags." do
          subject { false }
          it { should be true }
        end
      else
        impact 'medium'
        describe.one do
          sql_cache.instance_objects[db].settings.database_flags.each do |flag|
            next unless flag.name == 'log_duration'
            describe "[#{gcp_project_id} , #{db} ] should have a database flag 'log_duration' set to 'on' " do
              subject { flag }
              its('name') { should cmp 'log_duration' }
              its('value') { should cmp 'on' }
            end
          end
        end
      end
    else
      impact 'none'
      describe "[#{gcp_project_id}] [#{db}] is not a PostgreSQL database. This test is Not Applicable." do
        skip "[#{gcp_project_id}] [#{db}] is not a PostgreSQL database"
      end
    end
  end
end


# 6.2.6
sub_control_id = "#{control_id}.6"
control "cis-gcp-#{sub_control_id}-#{control_abbrev}" do
  impact 'medium'

  title "[#{control_abbrev.upcase}] Ensure that the 'log_lock_waits' database flag for Cloud SQL PostgreSQL instance is set to 'on'"

  desc 'Enabling the log_lock_waits flag for a PostgreSQL instance creates a log for any session waits that take longer than the alloted deadlock_timeout time to acquire a lock.'
  desc 'rationale', "The deadlock timeout defines the time to wait on a lock before checking for any conditions. Frequent run overs on deadlock timeout can be an indication of an
                    underlying issue. Logging such waits on locks by enabling the log_lock_waits flag can be used to identify poor performance due to locking delays or if a
                    specially-crafted SQL is attempting to starve resources through holding locks for excessive amounts of time."

  tag cis_scored: true
  tag cis_level: 1
  tag cis_gcp: sub_control_id.to_s
  tag cis_version: cis_version.to_s
  tag project: gcp_project_id.to_s
  tag nist: ['AU-3']

  ref 'CIS Benchmark', url: cis_url.to_s
  ref 'GCP Docs', url: 'https://cloud.google.com/sql/docs/postgres/flags#setting_a_database_flag'
  ref 'GCP Docs', url: 'https://www.postgresql.org/docs/9.6/runtime-config-logging.html#RUNTIME-CONFIG-LOGGING-WHAT'

  sql_cache.instance_names.each do |db|
    if sql_cache.instance_objects[db].database_version.include? 'POSTGRES'
      if sql_cache.instance_objects[db].settings.database_flags.nil?
        impact 'medium'
        describe "[#{gcp_project_id} , #{db} ] does not any have database flags." do
          subject { false }
          it { should be true }
        end
      else
        impact 'medium'
        describe.one do
          sql_cache.instance_objects[db].settings.database_flags.each do |flag|
            next unless flag.name == 'log_lock_waits'
            describe "[#{gcp_project_id} , #{db} ] should have a database flag 'log_lock_waits' set to 'on' " do
              subject { flag }
              its('name') { should cmp 'log_lock_waits' }
              its('value') { should cmp 'on' }
            end
          end
        end
      end
    else
      impact 'none'
      describe "[#{gcp_project_id}] [#{db}] is not a PostgreSQL database. This test is Not Applicable." do
        skip "[#{gcp_project_id}] [#{db}] is not a PostgreSQL database"
      end
    end
  end
end


# 6.2.8
sub_control_id = "#{control_id}.8"
control "cis-gcp-#{sub_control_id}-#{control_abbrev}" do
  impact 'medium'

  title "[#{control_abbrev.upcase}] Ensure 'log_hostname' database flag for Cloud SQL PostgreSQL instance is set appropriately"

  desc 'PostgreSQL logs only the IP address of the connecting hosts. The log_hostname flag controls the logging of hostnames in addition to the IP addresses logged.'
  desc 'rationale',  "Logging hostnames can incur overhead on server performance as for each statement
                      logged, DNS resolution will be required to convert IP address to hostname. Depending on
                      the setup, this may be non-negligible. Additionally, the IP addresses that are logged can be
                      resolved to their DNS names later when reviewing the logs excluding the cases where
                      dynamic hostnames are used. This recommendation is applicable to PostgreSQL database
                      instances."

  tag cis_scored: true
  tag cis_level: 1
  tag cis_gcp: sub_control_id.to_s
  tag cis_version: cis_version.to_s
  tag project: gcp_project_id.to_s
  tag nist: ['AU-3']

  ref 'CIS Benchmark', url: cis_url.to_s
  ref 'GCP Docs', url: 'https://cloud.google.com/sql/docs/postgres/flags'
  ref 'GCP Docs', url: 'https://www.postgresql.org/docs/current/runtime-config-logging.html#RUNTIME-CONFIG-LOGGING-WHAT'

  sql_cache.instance_names.each do |db|
    if sql_cache.instance_objects[db].database_version.include? 'POSTGRES'
      if sql_cache.instance_objects[db].settings.database_flags.nil?
        impact 'medium'
        describe "[#{gcp_project_id} , #{db} ] does not any have database flags." do
          subject { false }
          it { should be true }
        end
      else
        impact 'medium'
        describe.one do
          sql_cache.instance_objects[db].settings.database_flags.each do |flag|
            next unless flag.name == 'log_hostname'
            describe "[#{gcp_project_id} , #{db} ] should have a database flag 'log_hostname' set to 'on' " do
              subject { flag }
              its('name') { should cmp 'log_hostname' }
              its('value') { should cmp 'on' }
            end
          end
        end
      end
    else
      impact 'none'
      describe "[#{gcp_project_id}] [#{db}] is not a PostgreSQL database. This test is Not Applicable." do
        skip "[#{gcp_project_id}] [#{db}] is not a PostgreSQL database"
      end
    end
  end
end


# 6.2.9
sub_control_id = "#{control_id}.9"
control "cis-gcp-#{sub_control_id}-#{control_abbrev}" do
  impact 'medium'

  title "[#{control_abbrev.upcase}] Ensure 'log_parser_stats' database flag for Cloud SQL PostgreSQL instance is set to 'off'"

  desc 'The PostgreSQL planner/optimizer is responsible to parse and verify the syntax of each query received by the server.'
  desc 'rationale',  "The log_parser_stats flag enables a crude profiling method for logging parser
  performance statistics which even though can be useful for troubleshooting, it may
  increase the amount of logs significantly and have performance overhead. This
  recommendation is applicable to PostgreSQL database instances."

  tag cis_scored: true
  tag cis_level: 1
  tag cis_gcp: sub_control_id.to_s
  tag cis_version: cis_version.to_s
  tag project: gcp_project_id.to_s
  tag nist: ['AU-3']

  ref 'CIS Benchmark', url: cis_url.to_s
  ref 'GCP Docs', url: 'https://cloud.google.com/sql/docs/postgres/flags'
  ref 'GCP Docs', url: 'https://www.postgresql.org/docs/current/runtime-config-logging.html#RUNTIME-CONFIG-LOGGING-WHAT'
  ref 'GCP Docs', url: 'https://www.postgresql.org/docs/10/parser-stage.html'

  sql_cache.instance_names.each do |db|
    if sql_cache.instance_objects[db].database_version.include? 'POSTGRES'
      if sql_cache.instance_objects[db].settings.database_flags.nil?
        impact 'medium'
        describe "[#{gcp_project_id} , #{db} ] does not any have database flags." do
          subject { false }
          it { should be true }
        end
      else
        impact 'medium'
        describe.one do
          sql_cache.instance_objects[db].settings.database_flags.each do |flag|
            next unless flag.name == 'log_parser_stats'
            describe "[#{gcp_project_id} , #{db} ] should have a database flag 'log_parser_stats' set to 'off' " do
              subject { flag }
              its('name') { should cmp 'log_parser_stats' }
              its('value') { should cmp 'off' }
            end
          end
        end
      end
    else
      impact 'none'
      describe "[#{gcp_project_id}] [#{db}] is not a PostgreSQL database. This test is Not Applicable." do
        skip "[#{gcp_project_id}] [#{db}] is not a PostgreSQL database"
      end
    end
  end
end


# 6.2.10
sub_control_id = "#{control_id}.10"
control "cis-gcp-#{sub_control_id}-#{control_abbrev}" do
  impact 'medium'

  title "[#{control_abbrev.upcase}] Ensure 'log_planner_stats' database flag for Cloud SQL PostgreSQL instance is set to 'off'"

  desc 'The same SQL query can be excuted in multiple ways and still produce different results. '
  desc 'rationale',  "The log_planner_stats flag enables a crude profiling method for logging PostgreSQL
  planner performance statistics which even though can be useful for troubleshooting, it may
  increase the amount of logs significantly and have performance overhead. This
  recommendation is applicable to PostgreSQL database instances."

  tag cis_scored: true
  tag cis_level: 1
  tag cis_gcp: sub_control_id.to_s
  tag cis_version: cis_version.to_s
  tag project: gcp_project_id.to_s
  tag nist: ['AU-3']

  ref 'CIS Benchmark', url: cis_url.to_s
  ref 'GCP Docs', url: 'https://cloud.google.com/sql/docs/postgres/flags'
  ref 'GCP Docs', url: 'https://www.postgresql.org/docs/9.6/runtime-config-statistics.html#RUNTIME-CONFIG-STATISTICS-MONITOR'
  ref 'GCP Docs', url: 'https://www.postgresql.org/docs/9.5/planner-optimizer.html'

  sql_cache.instance_names.each do |db|
    if sql_cache.instance_objects[db].database_version.include? 'POSTGRES'
      if sql_cache.instance_objects[db].settings.database_flags.nil?
        impact 'medium'
        describe "[#{gcp_project_id} , #{db} ] does not any have database flags." do
          subject { false }
          it { should be true }
        end
      else
        impact 'medium'
        describe.one do
          sql_cache.instance_objects[db].settings.database_flags.each do |flag|
            next unless flag.name == 'log_planner_stats'
            describe "[#{gcp_project_id} , #{db} ] should have a database flag 'log_planner_stats' set to 'off' " do
              subject { flag }
              its('name') { should cmp 'log_planner_stats' }
              its('value') { should cmp 'off' }
            end
          end
        end
      end
    else
      impact 'none'
      describe "[#{gcp_project_id}] [#{db}] is not a PostgreSQL database. This test is Not Applicable." do
        skip "[#{gcp_project_id}] [#{db}] is not a PostgreSQL database"
      end
    end
  end
end


# 6.2.11
sub_control_id = "#{control_id}.11"
control "cis-gcp-#{sub_control_id}-#{control_abbrev}" do
  impact 'medium'

  title "[#{control_abbrev.upcase}] Ensure 'log_executor_stats' database flag for Cloud SQL PostgreSQL instance is set to 'off'"

  desc 'The PostgreSQL executor is responsible to execute the plan handed over by the PostgreSQL planner. '
  desc 'rationale',  "The log_executor_stats flag enables a crude profiling method for logging PostgreSQL
  executor performance statistics which even though can be useful for troubleshooting, it
  may increase the amount of logs significantly and have performance overhead. This
  recommendation is applicable to PostgreSQL database instances."

  tag cis_scored: true
  tag cis_level: 1
  tag cis_gcp: sub_control_id.to_s
  tag cis_version: cis_version.to_s
  tag project: gcp_project_id.to_s
  tag nist: ['AU-3']

  ref 'CIS Benchmark', url: cis_url.to_s
  ref 'GCP Docs', url: 'https://cloud.google.com/sql/docs/postgres/flags'
  ref 'GCP Docs', url: 'https://www.postgresql.org/docs/current/runtime-config-logging.html#RUNTIME-CONFIG-LOGGING-WHAT'
  ref 'GCP Docs', url: 'https://www.postgresql.org/docs/8.2/executor.html'

  sql_cache.instance_names.each do |db|
    if sql_cache.instance_objects[db].database_version.include? 'POSTGRES'
      if sql_cache.instance_objects[db].settings.database_flags.nil?
        impact 'medium'
        describe "[#{gcp_project_id} , #{db} ] does not any have database flags." do
          subject { false }
          it { should be true }
        end
      else
        impact 'medium'
        describe.one do
          sql_cache.instance_objects[db].settings.database_flags.each do |flag|
            next unless flag.name == 'log_executor_stats'
            describe "[#{gcp_project_id} , #{db} ] should have a database flag 'log_executor_stats' set to 'off' " do
              subject { flag }
              its('name') { should cmp 'log_executor_stats' }
              its('value') { should cmp 'off' }
            end
          end
        end
      end
    else
      impact 'none'
      describe "[#{gcp_project_id}] [#{db}] is not a PostgreSQL database. This test is Not Applicable." do
        skip "[#{gcp_project_id}] [#{db}] is not a PostgreSQL database"
      end
    end
  end
end


# 6.2.12
sub_control_id = "#{control_id}.12"
control "cis-gcp-#{sub_control_id}-#{control_abbrev}" do
  impact 'medium'

  title "[#{control_abbrev.upcase}] Ensure 'log_statement_stats' database flag for Cloud SQL PostgreSQL instance is set to 'off'"

  desc 'The log_statement_stats flag controls the inclusion of end to end performance statistics of a SQL query in the PostgreSQL logs for each query. '
  desc 'rationale',  "The log_statement_stats flag enables a crude profiling method for logging end to end
  performance statistics of a SQL query. This can be useful for troubleshooting but may
  increase the amount of logs significantly and have performance overhead. This
  recommendation is applicable to PostgreSQL database instances."

  tag cis_scored: true
  tag cis_level: 1
  tag cis_gcp: sub_control_id.to_s
  tag cis_version: cis_version.to_s
  tag project: gcp_project_id.to_s
  tag nist: ['AU-3']

  ref 'CIS Benchmark', url: cis_url.to_s
  ref 'GCP Docs', url: 'https://cloud.google.com/sql/docs/postgres/flags'
  ref 'GCP Docs', url: 'https://www.postgresql.org/docs/9.6/runtime-config-statistics.html#RUNTIME-CONFIG-STATISTICS-MONITOR'

  sql_cache.instance_names.each do |db|
    if sql_cache.instance_objects[db].database_version.include? 'POSTGRES'
      if sql_cache.instance_objects[db].settings.database_flags.nil?
        impact 'medium'
        describe "[#{gcp_project_id} , #{db} ] does not any have database flags." do
          subject { false }
          it { should be true }
        end
      else
        impact 'medium'
        describe.one do
          sql_cache.instance_objects[db].settings.database_flags.each do |flag|
            next unless flag.name == 'log_statement_stats'
            describe "[#{gcp_project_id} , #{db} ] should have a database flag 'log_statement_stats' set to 'off' " do
              subject { flag }
              its('name') { should cmp 'log_statement_stats' }
              its('value') { should cmp 'off' }
            end
          end
        end
      end
    else
      impact 'none'
      describe "[#{gcp_project_id}] [#{db}] is not a PostgreSQL database. This test is Not Applicable." do
        skip "[#{gcp_project_id}] [#{db}] is not a PostgreSQL database"
      end
    end
  end
end


# 6.2.14
sub_control_id = "#{control_id}.14"
control "cis-gcp-#{sub_control_id}-#{control_abbrev}" do
  impact 'medium'

  title "[#{control_abbrev.upcase}] Ensure that the 'log_min_error_statement' database flag for Cloud SQL PostgreSQL instance is set appropriately"

  desc 'The log_min_error_statement flag defines the minimum message severity level that is considered as an error statement. Messages for error statements are logged with the SQL statement '
  desc 'rationale', 'ERROR is considered the best practice setting. Auditing helps in troubleshooting operational problems and also permits forensic analysis. If log_min_error_statement is not set to the correct value, messages may not be classified as error messages appropriately'

  tag cis_scored: false
  tag cis_level: 1
  tag cis_gcp: sub_control_id.to_s
  tag cis_version: cis_version.to_s
  tag project: gcp_project_id.to_s
  tag nist: ['AU-3']

  ref 'CIS Benchmark', url: cis_url.to_s
  ref 'GCP Docs', url: 'https://cloud.google.com/sql/docs/postgres/flags#setting_a_database_flag'
  ref 'GCP Docs', url: 'https://www.postgresql.org/docs/9.6/runtime-config-logging.html#RUNTIME-CONFIG-LOGGING-WHAT'

  sql_cache.instance_names.each do |db|
    if sql_cache.instance_objects[db].database_version.include? 'POSTGRES'
      if sql_cache.instance_objects[db].settings.database_flags.nil?
        impact 'medium'
        describe "[#{gcp_project_id} , #{db} ] does not any have database flags." do
          subject { false }
          it { should be true }
        end
      else
        impact 'medium'
        describe.one do
          sql_cache.instance_objects[db].settings.database_flags.each do |flag|
            next unless flag.name == 'log_min_error_statement'
            describe "[#{gcp_project_id} , #{db} ] should have a database flag 'log_min_error_statement' set to 'ERROR' " do
              subject { flag }
              its('name') { should cmp 'log_min_error_statement' }
              its('value') { should cmp 'ERROR' }
            end
          end
        end
      end
    else
      impact 'none'
      describe "[#{gcp_project_id}] [#{db}] is not a PostgreSQL database. This test is Not Applicable." do
        skip "[#{gcp_project_id}] [#{db}] is not a PostgreSQL database"
      end
    end
  end
end

# 6.2.15
sub_control_id = "#{control_id}.15"
control "cis-gcp-#{sub_control_id}-#{control_abbrev}" do
  impact 'medium'

  title "[#{control_abbrev.upcase}] Ensure that the 'log_temp_files' database flag for Cloud SQL PostgreSQL instance is set to '0' (on)"

  desc 'PostgreSQL can create a temporary file for actions such as sorting, hashing and temporary query results when these operations exceed work_mem. The log_temp_files flag controls logging names and the file size when it is deleted.'
  desc 'rationale', 'If all temporary files are not logged, it may be more difficult to identify potential performance issues that may be due to either poor application coding or deliberate resource starvation attempts.'
  tag cis_scored: true
  tag cis_level: 1
  tag cis_gcp: sub_control_id.to_s
  tag cis_version: cis_version.to_s
  tag project: gcp_project_id.to_s
  tag nist: ['AU-3']

  ref 'CIS Benchmark', url: cis_url.to_s
  ref 'GCP Docs', url: 'https://cloud.google.com/sql/docs/postgres/flags#setting_a_database_flag'
  ref 'GCP Docs', url: 'https://www.postgresql.org/docs/9.6/runtime-config-logging.html#RUNTIME-CONFIG-LOGGING-WHAT'

  sql_cache.instance_names.each do |db|
    if sql_cache.instance_objects[db].database_version.include? 'POSTGRES'
      if sql_cache.instance_objects[db].settings.database_flags.nil?
        impact 'medium'
        describe "[#{gcp_project_id} , #{db} ] does not any have database flags." do
          subject { false }
          it { should be true }
        end
      else
        impact 'medium'
        describe.one do
          sql_cache.instance_objects[db].settings.database_flags.each do |flag|
            next unless flag.name == 'log_temp_files'
            describe "[#{gcp_project_id} , #{db} ] should have a database flag 'log_temp_files' set to '0' " do
              subject { flag }
              its('name') { should cmp 'log_temp_files' }
              its('value') { should cmp '0' }
            end
          end
        end
      end
    else
      impact 'none'
      describe "[#{gcp_project_id}] [#{db}] is not a PostgreSQL database. This test is Not Applicable." do
        skip "[#{gcp_project_id}] [#{db}] is not a PostgreSQL database"
      end
    end
  end
end

# 6.2.16
sub_control_id = "#{control_id}.16"
control "cis-gcp-#{sub_control_id}-#{control_abbrev}" do
  impact 'medium'

  title "[#{control_abbrev.upcase}] Ensure that the 'log_min_duration_statement' database flag for Cloud SQL PostgreSQL instance is set to '-1' (disabled)"

  desc 'The log_min_duration_statement flag defines the minimum amount of execution time of a statement in milliseconds where the total duration of the statement is logged.'
  desc 'rationale', 'Logging SQL statements may include sensitive information that should not be recorded in logs. This recommendation is applicable to PostgreSQL database instances.'

  tag cis_scored: true
  tag cis_level: 1
  tag cis_gcp: sub_control_id.to_s
  tag cis_version: cis_version.to_s
  tag project: gcp_project_id.to_s
  tag nist: ['AU-3']

  ref 'CIS Benchmark', url: cis_url.to_s
  ref 'GCP Docs', url: 'https://cloud.google.com/sql/docs/postgres/flags#setting_a_database_flag'
  ref 'GCP Docs', url: 'https://www.postgresql.org/docs/9.6/runtime-config-logging.html#RUNTIME-CONFIG-LOGGING-WHAT'

  sql_cache.instance_names.each do |db|
    if sql_cache.instance_objects[db].database_version.include? 'POSTGRES'
      if sql_cache.instance_objects[db].settings.database_flags.nil?
        impact 'medium'
        describe "[#{gcp_project_id} , #{db} ] does not any have database flags." do
          subject { false }
          it { should be true }
        end
      else
        impact 'medium'
        describe.one do
          sql_cache.instance_objects[db].settings.database_flags.each do |flag|
            next unless flag.name == 'log_min_duration_statement'
            describe "[#{gcp_project_id} , #{db} ] should have a database flag 'log_min_duration_statement' set to '-1' " do
              subject { flag }
              its('name') { should cmp 'log_min_duration_statement' }
              its('value') { should cmp '-1' }
            end
          end
        end
      end
    else
      impact 'none'
      describe "[#{gcp_project_id}] [#{db}] is not a PostgreSQL database. This test is Not Applicable." do
        skip "[#{gcp_project_id}] [#{db}] is not a PostgreSQL database"
      end
    end
  end
end
