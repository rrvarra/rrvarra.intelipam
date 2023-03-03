
# IntelPAM: Logstash Ruby Code Filter
##### Author: Ram Varra
###### Version 1.1


### Introduction
This filter solution is a Ruby Code filter to be used in logstash configuration to lookup IPAddresses in the input events and enrich the event with information from corresponding subnet found in Intel IPAM Range file.  Both IPV4 and IPV6 lookups are supported.

Lookups are performed by using `O(log(N))` computational cost using binary search tree algorithm. This will be signficantly faster compared to simple linear search. The time to lookup will be less than 10 microseconds per lookup for Intel production IPAM ranges.  Logstash can perform multiple lookups using worker threads providing high volume throughput pipeline.

### Example Configuration Section

The package includes an example logstah conf file `logstash_test.conf`.

```
filter {
  ruby {
    path => "logstash_ipam_filter.rb"
    script_params => {
      ipam_gz_dir => "path_to_gz_dir"
      source_field => ["IP"]
      refresh_interval_days => 1
    }
  }
}
```
### Example Input Event
```
{"IP" => "10.12.104.65"}
```
### Example Output
```
{
                    "IP" => "10.12.104.65",
             "IP_Region" => "GER",
    "IP_EnvironmentCode" => "IES",
           "IP_Function" => "Internal Link or Rail",
              "IP_Title" => "v929-IESINT-PEL-VPG",
       "IP_FunctionCode" => "INT",
            "IP_SiteLoc" => { "lon" => 35.21371, "lat" =>31.768319},
           "IP_SiteCode" => "IS",
              "IP_Range" => "10.12.104.64/29",
       "IP_BuildingCode" => "JER5",
                "IP_VPN" => false,
           "IP_SiteName" => "Israel, Jerusalem",
            "IP_Country" => "ISRAEL",
           "IP_Building" => "Jerusalem 5 Office Bldg",
        "IP_Environment" => "Internal Enclave Services"
}
```

### Configuration Parameters

* **path (string, mandatory)**: Specifies the ruby code file. This file is included with this package and must be copied into the current folder where you are running logstash. Do not modify this file.

* **script_params.ipam_gz_dir (string, mandatory)**: This parameter specifics folder that contains the IPAMRange files. The most recent file is selected from this folder.  These files must be either created with [rv.IntelIPAM](https://github.intel.com/rrvarra/rv3/blob/master/IntelIPAM.py) using download option or obtained from `\\FMS-GNM-DBM-A3\RVSHARE\IntelIPAMRanges` folder. The files in this folder should have `Intel_IPAM_Ranges-*.gz` format.  This should be preferably local folder to avoid dependency on the  remote systems at run time.  Latest file from this folder is read at the time logstash starts. Subsequently the script checks for new files after each `refresh_interval_days` and reloads if there is a more recent file in the folder.

* **script_params.refresh_interval_days (integer)**: Frequency in days to check for newer files in `ipam_gz_dir` folder.  If there is a newer file, will load it for future lookups.

* **source_field (string or array of strings, mandatory)**: Field or list of fields to do lookups on.  For each field looked up, the event will be enriched with additional informational fields such as SiteCode, Function, etc.  The enriched fields will include source_field as prefix followed by `_`.  Non existing source_fields will be silently ignored.  Any existing fields with new enriched field names will be overwritten.  Failed lookups are silently ignored.
