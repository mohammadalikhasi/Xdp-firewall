/* This common_kern_user.h is used by kernel side BPF-progs and
 * userspace programs, for sharing common struct's and DEFINEs.
 */
#ifndef __COMMON_KERN_USER_H
#define __COMMON_KERN_USER_H

/* This is the data record stored in the map */
struct datarec {
	__u64 rx_packets;
	__u64 rx_bytes;
};

#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX 2
#endif

#ifndef badip
#define badip 0x0100007f
#endif

#ifndef badportl
#define badportl 85
#endif

#ifndef badporth
#define badporth 100
#endif

#endif /* __COMMON_KERN_USER_H */
