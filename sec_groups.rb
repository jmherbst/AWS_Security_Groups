#!/usr/bin/env ruby

require 'fog'
require 'json'
require 'logger'  

class String
  def to_range
    nums = self.split('..')
    return Range.new(nums[0].to_i, nums[1].to_i)
  end
end

log = Logger.new(STDOUT)
log.level = Logger::WARN

# Loads AWS creds from file: ~/.fog
begin
  log.debug "Looking in #{Dir.home}/.fog for AWS Credentials"
  settings = YAML.load_file("#{Dir.home}/.fog")
rescue
  log.error "No AWS credentials found in #{Dir.home}/.fog"
  log.error "Exiting due to failure..."
  exit 3
end

log.debug "Found AWS Credentials..."

begin
  log.debug "Attempting to initialize new Fog::Compute object using AWS Credientials from #{Dir.home}/.fog"

  compute = Fog::Compute.new({
    :provider => 'AWS',
    :aws_access_key_id => settings['aws']['access_key_id'],
    :aws_secret_access_key => settings['aws']['secret_access_key']
  })
rescue Exception => e
  log.error "Unable to intialize Fog::Compute object. #{e.class} -- #{e.message.gsub("\n"," ")}"
end

log.debug "Fog::Compute object created succesfully"

groups = []   # Array to hold hash's harvested from json security groups
begin
  log.debug "Beginning to parse through all *.json files in current working directory"
  Dir.open(Dir.pwd).each do |file|
    if file =~ /.json$/       # Only read from *.json files in current directory
      log.debug "Parsing #{Dir.pwd}/#{file}"
      groups.push(JSON.parse(File.read(file)))
    end
  end
  log.debug "File parsing complete"
rescue JSON::ParserError => e
  log.error "JSON Parse Error #{e.message.gsub("\n"," ")}"
rescue Exception => e
  log.error "#{e.class} -- #{e.message.gsub("\n"," ")}"
end

# Looping through groups harvested from *.json files to authorize in/out bound rules
groups.each do |group|
  security_group = compute.security_groups.get_by_id(group["security_group"]["group_id"])
  group["security_group"]["inbound"]["rules"].each do |rule|    
    if rule["source"] =~ /^sg-.*$/      # Determining whether source is an IP or a Security Group ID and setting options hash key appropriately 
      ops = {:group => rule["source"]}
    else
      begin
        raise ArgumentError, "Invalid soure IP syntax in JSON -- Must be in CIDR Notation" unless rule["source"] =~ /^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[0-9]{1,2}$/   # Super ugly regex for an IPv4 address in CIDR Notation. ex: 10.1.1.1/32
        ops = {:cidr_ip => rule["source"]}
      rescue ArgumentError => e
        ops = nil
        log.error "#{e.class} -- #{e.message}"
      end
    end

    # destination_ports from .json are strings. Must convert to Range
    ports = rule["destination_ports"].to_range

    unless ops == nil   # Only attempt to authorize the port if ops was succesfully created.  
      begin
        log.debug "Authorizing Inbound port range in #{group["security_group"]["name"]}(#{group["security_group"]["group_id"]}) for SOURCE: #{ops} -- PORT_RANGE: #{ports}"
        security_group.authorize_port_range(ports, ops)
      rescue Fog::Compute::AWS::Error => e
        if e.to_s =~ /Duplicate/
          log.warn "Duplicate rule already exists in #{group["security_group"]["name"]}(#{group["security_group"]["group_id"]}) for SOURCE: #{ops} -- PORT_RANGE: #{ports}.  Skipping ..."
        else
          log.warn "Error authorizing port range. SOURCE: #{ops} -- PORT_RANGE: #{ports}"
        end
      end
    end
  end
end
