# ipam ruby filter
# Author: Ram Varra
# V2
require "logstash/filters/base"
require "logstash/namespace"
require 'zlib'
require 'json'
require 'ipaddr'
java_import 'java.util.concurrent.locks.ReentrantReadWriteLock'

# ------------------------------------------------------------------------------
def log_info(s)
  ts = Time.now.strftime('%Y-%m-%d %H:%M:%S')
  puts "#{ts} - #{s}"
end

# ------------------------------------------------------------------------------
# runs a block with thread readlock
def lock_for_read
  @read_lock.lock
  begin
    yield
  ensure
    @read_lock.unlock
  end
end

# ------------------------------------------------------------------------------
# runs a block with thread writelock
def lock_for_write
  @write_lock.lock
  begin
    yield
  ensure
    @write_lock.unlock
  end
end

# ------------------------------------------------------------------------------
# Return latest .gz file path from path glob pattern
# Files should be of the format: Intel_IPAM_Ranges-*.gz
# these files must be created with rv.IntelIPAM module with
# download option.
def get_latest_intel_ipam_gz_file(dir_path)
  raise "dir_path must be directory #{dir_path}" unless File.directory?(dir_path)
  files = Dir.new(dir_path).select {|f|
    File.fnmatch("Intel_IPAM_Ranges-*.gz", f)
  }.map {|f|
    File.join(dir_path, f)
  }
  sorted_files = files.map {|f| [File.mtime(f), f]}.sort
  raise "No files found matching Intel_IPAM_Ranges-*.gz glob in #{dir_path}" unless sorted_files.size > 0
  return sorted_files[-1][1]
end

# ------------------------------------------------------------------------------
def load_master_block(gz_file)
  master_block = nil
  log_info "Loading gz file: #{gz_file}"
  begin
    Zlib::GzipReader.open(gz_file) { |gzfd|
      json_text = gzfd.read
      begin
        master_block = JSON::parse(json_text)
      rescue Exception => ex
        raise "Exception while loading master_block from #{gz_file}: #{ex.message}"
      end
    }
  rescue Exception => ex
    raise "Exception while reading gzip #{gz_file}: #{ex.message}"
  end

  return master_block
end

# ------------------------------------------------------------------------------
def binary_search(info_list, ipa_int)
  first = 0
  last = info_list.size - 1
  while first <= last
    i = (first + last) / 2
    b = info_list[i]['IP_START']
    e = info_list[i]['IP_END']

    if ipa_int >= b and ipa_int <= e
      return info_list[i]['INFO']
    end
    if ipa_int < b then
      last = i - 1
    elsif ipa_int > e then
      first = i + 1
    else
      return nil
    end
  end
  return nil
end

# ------------------------------------------------------------------------------
def lookup_ip(ip)
  ipa = IPAddr.new(ip)
  ipa_int = ipa.to_i
  v = ipa.ipv4? ? "4": "6"
  mbv = @master_block[v]
  mbv.each {|subnet_block_dict|
    subnet_block_dict.each {|range_size, block|
      result = binary_search(block, ipa_int)
      return result unless result.nil?
    }
  }
  return nil
end

# ------------------------------------------------------------------------------
def needs_refresh?
  return (Time.now > @next_refersh)
end

# ------------------------------------------------------------------------------
def refresh_master_block()
  #log_info "MB Refresh"
  lock_for_write do
    if needs_refresh?
      latest_ipam_file = get_latest_intel_ipam_gz_file(@ipam_gz_dir)
      if (@ipam_gz_file.nil? || latest_ipam_file != @ipam_gz_file)
        @ipam_gz_file = latest_ipam_file
        @master_block = load_master_block(@ipam_gz_file)
      end
      @next_refersh = Time.now + @refresh_interval
    end
  end
end
# ------------------------------------------------------------------------------
# this code runs once per filter startup
def register(params)

  rw_lock = java.util.concurrent.locks.ReentrantReadWriteLock.new
  @read_lock = rw_lock.readLock
  @write_lock = rw_lock.writeLock

  @ipam_gz_dir = params["ipam_gz_dir"]
  raise "Mandtory parameter ipam_gz_dir not defined" if @ipam_gz_dir.nil?

  # make it ruby friendly for windows paths
  @ipam_gz_dir = @ipam_gz_dir.tr('\\', '/')

  @refresh_interval = params["refresh_interval_days"] || 1 # will need to make daily
  raise "Invalid referesh_interval_days #{@refresh_interval} must be integer and > 0" unless (@refresh_interval.is_a? Integer and @refresh_interval > 0)
  @refresh_interval *= (24*3600) #convert to secs

  @log_file = params["log_file"]  #'C:\TEMP\ipam_rb.log'

  @source_field = params["source_field"]
  raise "Mandtory parameter source_field not defined" if @source_field.nil?
  @source_field = [@source_field] if  @source_field.instance_of?(String)
  #log_info("rb:register: source_field = #{@source_field}")

  @ipam_gz_file = nil
  @master_block = nil
  @next_refersh = nil
  #log_info("Loading master_block from : #{@ipam_gz_dir}")
  lock_for_write {
    @ipam_gz_file = get_latest_intel_ipam_gz_file(@ipam_gz_dir)
    @master_block = load_master_block(@ipam_gz_file)
    @next_refersh = Time.now + @refresh_interval
  }

  #log_info("Init Success")
end

# ------------------------------------------------------------------------------
# this code runs for each event
def filter(event)
  return [event] if @source_field.nil?

  refresh_master_block if needs_refresh?

  for src_field in @source_field
    ip = event.get(src_field)
    if not ip.nil?
      #log_info("Looking up #{ip}")
      r = lock_for_read { lookup_ip(ip) }

      #log_info("Lookup Result: #{r}")
      if not r.nil?
        r.each do |k,v|
          event.set("#{src_field}_#{k}", v)
        end
      else
        event.tag("ipam_lookup_failed")
      end

      #log_info("Set event success.")
    end

  end

  return [event]
end

# --------------------------------------------------------------------------------------------------------------------
# test suite
# --------------------------------------------------------------------------------------------------------------------
test "TEST1: Existing IP" do
    parameters do
        {
          "source_field" => ["IP", "IP2"],
          "ipam_gz_dir" => 'ipam_gz_dir'
        }
    end

    in_event {
      [
        {"IP" => "10.12.104.65"},
        {"IP" => "192.168.104.10"},
        {"IP" => "10.12.104.65",  "IP2" => "10.3.86.129"}
      ]
    }
    expect("TEST1: IPAM_LOOKUP") do |events|
       # TEST 2:
        kv = {"IP" => "10.12.104.65",
          "IP_VPN" => false,
          "IP_BuildingCode" => "JER5",
          "IP_EnvironmentCode" => "IES",
          "IP_SiteCode" => "IS",
          "IP_Range" => "10.12.104.64/29",
          "IP_Country" => "ISRAEL",
          "IP_SiteLoc" => {
            "lat" => 31.768319,
            "lon" => 35.21371
          },
          "IP_Building" => "Jerusalem 5 Office Bldg",
          "IP_Title" => "v929-IESINT-PEL-VPG",
          "IP_Environment" => "Internal Enclave Services",
          "IP_Region" => "GER",
          "IP_SiteName" => "Israel, Jerusalem",
          "IP_FunctionCode" => "INT",
          "IP_Function" => "Internal Link or Rail",
        }

        #puts "TEST1: IPAM_LOOKUP"
        test_1_ok = true
        kv.each do |k,v|
          test_1_ok = false unless events[0].get(k) == v
        end
        puts (test_1_ok ? "TEST1: SUCCESS": "TEST1: FAILED")

        # TEST 2:
        #puts "TEST2: Non existing IP"
        fields = ["IP_VPN", "IP_BuildingCode", "IP_EnvironmentCode", "IP_SiteCode",
          "IP_Range", "IP_Function"]
        test_2_ok = true
        fields.each do |k|
          test_2_ok = false unless events[1].get(k).nil?
        end
        puts (test_2_ok ? "TEST2: SUCCESS": "TEST2: FAILED")

        # TEST3: Multiple IP
        kv = {
          "IP" => "10.12.104.65",
          "IP_Range" => "10.12.104.64/29",
          "IP2" => "10.3.86.129",
          "IP2_Range" => "10.3.86.128/28"
        }

        #puts "TEST3: Multiple IP"
        test_3_ok = true
        kv.each do |k,v|
          test_3_ok = false unless events[2].get(k) == v
        end
        puts (test_3_ok ? "TEST3: SUCCESS": "TEST3: FAILED")

        test_1_ok && test_2_ok && test_3_ok

    end
end
