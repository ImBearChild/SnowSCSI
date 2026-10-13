/*
 * ABI-safe accessors into struct scsi_task (libiscsi), compiled by `cc`
 * in build.rs against the same headers libiscsi was built with. Field
 * offsets are therefore guaranteed correct — the Rust FFI side only ever
 * handles opaque pointers and never assumes struct layout.
 *
 */
#include <stddef.h>
#include <stdint.h>
#include <iscsi/scsi-lowlevel.h>

int snow_task_status(const struct scsi_task *t)
{
    return t->status;
}

int snow_task_datain_size(const struct scsi_task *t)
{
    return t->datain.size;
}

const void *snow_task_datain_data(const struct scsi_task *t)
{
    return t->datain.data;
}

int snow_task_sense_key(const struct scsi_task *t)
{
    return t->sense.key;
}
