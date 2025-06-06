@load base/files/extract
@load policy/protocols/conn/mac-logging
@load base/frameworks/files

redef FileExtract::default_limit = 0;
redef FileExtract::default_limit_includes_missing = F;
redef ignore_checksums = T;

# All configuration must occur within this file.
# All other files may be overwritten during upgrade 
module FileExtraction;

# Configure where extracted files will be stored
redef path = "/opt/zeek/extracted/";

# Configure 'plugins' that can be loaded
# these are shortcut modules to specify common 
# file extraction policies. Example:
# @load ./plugins/extract-pe.bro
# @load ./plugins/extract-common-exploit-types
@load ./plugins/extract-skripsi