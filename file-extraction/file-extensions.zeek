module FileExtraction;

export {
	## Map file extensions to file mime_type
	const mime_to_ext: table[string] of string = {
		["application/x-dosexec"] = "exe",
		["application/msword"] = "doc",
		["application/x-dmg"] = "dmg",
		["application/x-gzip"] = "gz",
		["application/x-rar"] = "rar",
		["application/x-tar"] = "tar",
		["application/x-xar"] = "pkg",
		["application/x-rpm"] = "rpm",
		["application/x-stuffit"] = "sif",
		["application/x-archive"] = "",
		["application/x-arc"] = "arc",
		["application/x-eet"] = "eet",
		["application/x-zoo"] = "zoo",
		["application/x-lz4"] = "lz4",
		["application/x-lrzip"] = "lrz",
		["application/x-lzh"] = "lzh",
		["application/warc"] = "warc",
		["application/x-7z-compressed"] ="7z",
		["application/x-xz"] = "xz",
		["application/x-lha"] = "lha",
		["application/x-arj"] = "arj",
		["application/x-cpio"] = "cpio",
		["application/x-compress"] = "",
		["application/x-lzma"] = "",
		["application/zip"] = "zip",
		["application/vnd.ms-cab-compressed"] = "cab",
		["application/pdf"] = "pdf",
		["application/vnd.openxmlformats-officedocument.wordprocessingml.document"] = "docx",
		["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"] = "xlsx",
		["application/vnd.openxmlformats-officedocument.presentationml.presentation"] ="pptx",
		["application/font-woff"] = "woff",
		["application/x-font-ttf"] = "ttf",
		["application/vnd.ms-fontobject"] = "eot",
		["application/x-font-sfn"] = "",
		["application/vnd.ms-opentype"] = "otf",
		["application/x-mif"] = "mif",
		["application/vnd.font-fontforge-sfd"] = "sfd",
		["audio/mpeg"] = "mp3",
		["audo/m4a"] = "mp4",
		["image/tiff"] = "tiff",
		["image/gif"] = "gif",
		["image/jpeg"] = "jpg",
		["image/x-ms-bmp"] = "bmp",
		["image/x-icon"] = "ico",
		["image/x-cursor"] = "cur",
		["image/vnd.adobe.photoshop"] = "pnd",
		["image/png"] = "png",
		["text/html"] = "html",
		["text/plain"] = "txt",
		["text/json"] = "json",
		["text/rtf"] = "rtf",
		["application/xml"] = "xml",
		["text/rss"] = "rss",
		["application/java-archive"] = "jar",
		["application/x-java-applet"] = "jar",
		["application/x-shockwave-flash"] = "swf",
		["application/pkcs7-signature"] = "p7",
		["application/x-pem"] = "pem",
		["application/x-java-jnlp-file"] = "jnlp",
		["application/vnd.tcpdump.pcap"] = "pcap",
		["text/x-shellscript"] = "sh",
		["text/x-perl"] = "pl",
		["text/x-ruby"] = "rb",
		["text/x-python"] = "py",
		["text/x-awk"] = "awk",
		["text/x-lua"] ="lua",
		["application/javascript"] = "js",
		["text/x-php"] = "php",
		["application/x-executable"] = "",
		["application/x-coredump"] = "core",
		["video/x-flv"] = "flv",
		["video/x-fli"] = "fli",
		["video/x-flc"] = "flc",
		["video/mj2"] = "mj2",
		["video/x-mng"] = "mng",
		["video/x-jng"] = "jng",
		["video/mpeg"] = "mpg",
		["video/mpv"] = "mpv",
		["video/h264"] = "264",
		["video/webm"] = "webm",
		["video/matroska"] = "mkv",
		["vidoe/x-sgi-movie"] = "sgi",
		["video/quicktime"] = "qt",
		["video/mp4"] = "mp4",
		["video/3gpp"] = "3gp",
		["text/csv"] = "csv",
        ["application/csv"] = "csv",  
	};
}
