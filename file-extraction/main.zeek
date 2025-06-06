@load ./file-extensions
module FileExtraction;

export {
    const path: string        = "/opt/zeek/extracted/" &redef;
    const save_metadata: bool = T &redef;

    global extract: hook(f: fa_file, meta: fa_metadata);
    global ignore:  hook(f: fa_file, meta: fa_metadata);
}

# -------------------------------------------------------------------
# 1.  Define a clear record type for network + MAC information
# -------------------------------------------------------------------
type NetInfo: record {
    src_ip:   addr;
    src_port: port;
    dst_ip:   addr;
    dst_port: port;
    src_mac:  string &optional;
    dst_mac:  string &optional;
};

# -------------------------------------------------------------------
# 2.  Map connection-UID → NetInfo, expiring after 2 minutes
# -------------------------------------------------------------------
global uid_to_net: table[string] of NetInfo &write_expire = 2min;

event new_connection(c: connection)
    {
    uid_to_net[c$uid] = [$src_ip   = c$id$orig_h,
                         $src_port = c$id$orig_p,
                         $dst_ip   = c$id$resp_h,
                         $dst_port = c$id$resp_p,
                         $src_mac  = c$orig?$l2_addr ? c$orig$l2_addr : "",
                         $dst_mac  = c$resp?$l2_addr ? c$resp$l2_addr : ""];
    }

# -------------------------------------------------------------------
# 3.  Basic file extraction (unchanged from your working version)
# -------------------------------------------------------------------
event file_sniff(f: fa_file, meta: fa_metadata)
    {
    if ( meta?$mime_type && ! hook FileExtraction::extract(f, meta) )
        {
        if ( !hook FileExtraction::ignore(f, meta) )
            return;

        local ext = meta$mime_type in mime_to_ext
                   ? mime_to_ext[meta$mime_type]
                   : split_string(meta$mime_type, /\//)[1];

        local fname = fmt("%s%s-%s.%s",
                          path, f$source, f$id, ext);

        Files::add_analyzer(f, Files::ANALYZER_EXTRACT,
                            [$extract_filename = fname]);
        }
    }

# -------------------------------------------------------------------
# 4.  Write side-car JSON when the file is finished
# -------------------------------------------------------------------
event file_state_remove(f: fa_file)
    {
    if ( ! save_metadata || ! f$info?$extracted )
        return;

    # ---- build JSON ------------------------------------------------
    local rec: table[string] of string = table();
    rec["id"]        = f$id;
    rec["source"]    = f$source;
    rec["extracted"] = f$info$extracted;

    if ( f$info?$filename )    rec["filename"]  = f$info$filename;
    if ( f$info?$mime_type )   rec["mime_type"] = f$info$mime_type;
    if ( f$info?$md5 )         rec["md5"]       = f$info$md5;
    # if ( f$info?$total_bytes ) rec["size"]      = cat(f$info$total_bytes);

    local bytes = f$info?$total_bytes ? f$info$total_bytes : f$info$seen_bytes;
    rec["size"] = fmt("%d", bytes);

    rec["ts"]        = fmt("%s", network_time());

    # ---- attach IP/port/MAC via the single UID available in Zeek 8 --
    for ( cid in f$conns )
        {
        local conn_rec = f$conns[cid];          # this is a record with .uid, .is_orig, etc.
        local cuid     = conn_rec$uid;          # the connection UID
        if ( cuid in uid_to_net )               # did we see it in our new_connection map?
            {
            local n = uid_to_net[cuid];
            rec["src_ip"]   = fmt("%s", n$src_ip);
            rec["src_port"] = fmt("%d", n$src_port);
            rec["dst_ip"]   = fmt("%s", n$dst_ip);
            rec["dst_port"] = fmt("%d", n$dst_port);
            if ( n?$src_mac && n$src_mac != "" )
                rec["src_mac"] = n$src_mac;
            if ( n?$dst_mac && n$dst_mac != "" )
                rec["dst_mac"] = n$dst_mac;
            break;   # once we’ve filled in one matching connection, stop
            }
        }

    # ---- write the .meta file --------------------------------------
    local out_path  = fmt("%s.meta", f$info$extracted);
    local json_data = to_json(rec);

    when [ json_data, out_path, f ] ( local out = open(out_path) )
        {
        print out, json_data;
        close(out);
        }
    timeout 5sec
        {
        Reporter::warning(fmt("Failed to write metadata for %s",
                              f$info$extracted));
        }
    }