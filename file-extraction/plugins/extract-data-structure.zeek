@load ../__load__

module FileExtraction;

# Define the set of image MIME types we want to extract
const image_types: set[string] = {
    "text/csv",
    "application/csv,
};

# Hook into the extraction system with a reasonable priority (5 is same as MS Office)
hook FileExtraction::extract(f: fa_file, meta: fa_metadata) &priority=5
{
    if (meta$mime_type in image_types)
        break;
}