/*
 * ABI-safe accessors into struct scsi_task (libiscsi) plus the two transport
 * helpers the async tests need, compiled by `cc` in build.rs against the same
 * headers libiscsi was built with. Field offsets are therefore guaranteed
 * correct — the Rust FFI side only ever handles opaque pointers and never
 * assumes struct layout.
 *
 */
#include <errno.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <iscsi/iscsi.h>
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

/* The sense ASC/ASCQ pair as libiscsi stores it: (ASC << 8) | ASCQ. */
int snow_task_sense_ascq(const struct scsi_task *t)
{
    return t->sense.ascq;
}

/* Initiator Task Tag the target will see for this command. Needed to address
 * it from a task-management request. */
uint32_t snow_task_itt(const struct scsi_task *t)
{
    return t->itt;
}

/*
 * Pump one poll(2) round of the libiscsi event loop.
 *
 * libiscsi's blocking helpers own their own loop, so an in-flight command can
 * only be observed by driving the socket from outside: poll the connection fd
 * for `events` (POLLIN and/or POLLOUT) and hand the result to iscsi_service().
 *
 * Returns 1 when events were serviced, 0 on timeout (nothing happened), and -1
 * when the library reported an error.
 */
int snow_iscsi_pump(struct iscsi_context *iscsi, int events, int timeout_ms)
{
    struct pollfd pfd;
    int rc;

    pfd.fd = iscsi_get_fd(iscsi);
    if (pfd.fd < 0) {
        return -1;
    }
    pfd.events = (short)events;
    pfd.revents = 0;

    rc = poll(&pfd, 1, timeout_ms);
    if (rc < 0) {
        return errno == EINTR ? 0 : -1;
    }
    if (rc == 0) {
        return 0;
    }
    return iscsi_service(iscsi, pfd.revents) < 0 ? -1 : 1;
}

/*
 * Sever the TCP connection under a live libiscsi context.
 *
 * iscsi_disconnect() performs a logout first, which services the socket and
 * therefore lets an in-flight transfer run to completion; a mid-transfer drop
 * needs the transport itself torn down. shutdown(2) on the context's fd sends
 * FIN and makes every later read/write fail.
 */
int snow_iscsi_drop(struct iscsi_context *iscsi)
{
    int fd = iscsi_get_fd(iscsi);

    if (fd < 0) {
        return -1;
    }
    return shutdown(fd, SHUT_RDWR);
}
