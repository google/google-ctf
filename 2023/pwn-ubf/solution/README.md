# Google CTF 2023 - pwn: UBF writeup

In the task, we get a source code of some custom serialization format, which we need to pwn. After reading through the source, we notice some interesting features. It has "string interpolation" - i.e. it will replace "$FLAG" with the corresponding environmental variable. However, it censors interpolated strings, so that if it contains "CTF{", the flag is replaced with multiple X's. For booleans, it also has a "fixing" functionality - which will cast any value to 0 or 1.

The parser works in two phases. First (`unpack_entry` function), it unpacks entries into an intermediate, linked list representation in memory. It also fixes corrupted booleans there. During the second phase (second half of the `unpack` function), it stringifies the arrays and eventually prints them. Strings are here interpolated and censored.

The data format structure is as follows:
```
struct ubf_packed {
  int block_size;
  char type;
  short count;
  short metadata_size;
  // metadata[metadata_size]
  // data[count]
};
```

Block size corresponds to the full size of necessary memory for the unpacked array (e.g. for ints, it should be 4*count). Type is an enum for data type. Count is the number of entries in the array. Metadata_size is only really used for string arrays, where it contains lengths of the strings - for other arrays, it is mostly ignored. The above structure is partially sanitized during parsing - block size and count is checked against being negative. However, metadata size is not.

For strings, there is this check:
```
  if (packed->metadata_size != packed->count * sizeof(short))
```
The right hand side will be casted to a size_t, so we cannot abuse integer overflow here - hence metadata_size needs to be correct here as well.

However, there is one more place where metadata_size is also used - in the `fix_corrupt_booleans` function:
```
  char* data = (char*)unpacked->raw_data + unpacked->metadata_size;
  char* end = (char*)unpacked->raw_data + unpacked->raw_size;
  for (int i = 0; i < unpacked->count; ++i) {
    if (data + i >= end) break;
    data[i] = !!data[i];
  }
```
Here, if metadata_size is negative (and it is not checked against it!), we can overwrite entries before the current one. So we can exploit it by first creating an entry with a flag (that is currently uncensored), then an entry with a bool array and negative metadata_size field. We can set that field to such a value, that one of the "CTF{" characters is overwritten. Then the censorship won't be triggered and the whole flag is printed (except for one of the characters)
