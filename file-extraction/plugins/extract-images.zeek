@load ../__load__

module FileExtraction;

# Define the set of image MIME types we want to extract
const image_types: set[string] = {
    "image/tiff",
    "image/gif", 
    "image/jpeg",
    "image/x-ms-bmp",
    "image/x-icon",
    "image/x-cursor",
    "image/vnd.adobe.photoshop",
    "image/png"
};

# Hook into the extraction system with a reasonable priority (5 is same as MS Office)
hook FileExtraction::extract(f: fa_file, meta: fa_metadata) &priority=5
{
    if (meta$mime_type in image_types)
        break;
}