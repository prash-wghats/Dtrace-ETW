/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2012, Joyent, Inc. All rights reserved.
 */

 #pragma D depends_on library types.d
/*#pragma D depends_on module ntkernel
#pragma D depends_on provider io
*/

/*inline int B_BUSY = @B_BUSY@;
#pragma D binding "1.0" B_BUSY
inline int B_DONE = @B_DONE@;
#pragma D binding "1.0" B_DONE
inline int B_ERROR = @B_ERROR@;
#pragma D binding "1.0" B_ERROR
inline int B_PAGEIO = @B_PAGEIO@;
#pragma D binding "1.0" B_PAGEIO
inline int B_PHYS = @B_PHYS@;
#pragma D binding "1.0" B_PHYS*/
inline int B_READ = 0x01;
#pragma D binding "1.0" B_READ
inline int B_WRITE = 0x02;
#pragma D binding "1.0" B_WRITE
inline int B_FLUSH = 0x04;
#pragma D binding "1.0" B_FLUSH
/*inline int B_ASYNC = @B_ASYNC@;
#pragma D binding "1.0" B_ASYNC*/

typedef struct bufinfo {
	int b_flags;			/* buffer status */
	int b_irpflags;			/* I/O request packet flags */
	size_t b_bcount;		/* number of bytes */
	caddr_t b_addr;			/* buffer address */
	uint64_t b_lblkno;		/* block # on device */
	uint64_t b_blkno;		/* expanded block # on device */
	size_t b_resid;			/* # of bytes not transferred */
	size_t b_bufsize;		/* size of allocated buffer */
	caddr_t b_iodone;		/* I/O completion routine */
	int b_error;			/* expanded error field */
	int b_edev;				/* extended device */
	uint64_t resp;			/* The time between I/O initiation and completion */
} bufinfo_t;

#pragma D binding "1.0" translator
translator bufinfo_t < struct buf *B > {
	b_flags = B->b_flags;
	b_irpflags = B->b_irpflags;
	b_addr = B->b_irpaddr;
	b_bcount = B->b_bcount;
	b_lblkno = 0;
	b_blkno = 0;
	b_resid = 0;
	b_bufsize = 0;
	b_iodone = 0;
	b_error = 0;
	b_edev = B->b_diskno;
}; 

typedef struct devinfo {
	int dev_major;			/* major number */
	int dev_minor;			/* minor number */
	int dev_instance;		/* instance number */
	string dev_name;		/* name of device */
	string dev_statname;		/* name of device + instance/minor */
	string dev_pathname;		/* pathname of device */
} devinfo_t;

#pragma D binding "1.0" translator
translator devinfo_t < struct buf *B > {
	dev_major = 0;
	dev_minor = 0;
	dev_instance = 0;
	dev_name = "?";
	dev_statname = B->b_fname == NULL ? "":substr(wstringof(B->b_fname), 0, 2);
	dev_pathname = "?";
};

typedef struct fileinfo {
	string fi_name;			/* name (basename of fi_pathname) */
	string fi_dirname;		/* directory (dirname of fi_pathname) */
	string fi_pathname;		/* full pathname */
	uint64_t fi_offset;		/* offset within file */
	string fi_fs;			/* filesystem */
	string fi_mount;		/* mount point of file system */
	int fi_oflags;			/* open(2) flags for file descriptor */
	int fi_cflags;			/* create options */
	int fi_aflags;			/* File attributes */
	int fi_sflags;			/* File share access flags */
	int fi_bcount;			/* number of bytes requested*/ 
	int fi_extinfo;			/* extra info */
	int fi_rstatus;			/* return (NTSTATUS) status */
	int fi_dbuflen;			/* directory enum buffer size */
	caddr_t fi_irp;         /* unique irp address */
	string fi_dpattern;		/* directory search pattern */
} fileinfo_t;

#pragma D binding "1.0" translator
translator fileinfo_t < struct buf *B > {
	fi_name = B->b_fname == NULL ? "<none>" :
	    basename(wstringof(B->b_fname));
	fi_dirname = B->b_fname == NULL ? "<none>" :
	    dirname(wstringof(B->b_fname));
	fi_pathname = B->b_fname == NULL ? "<none>" :
	    wstringof(B->b_fname);
	fi_offset = B->b_offset;
	fi_fs = "?";
	fi_mount = "?";
	fi_oflags = 0;
};

#pragma D binding "1.0" translator
translator fileinfo_t < struct wfileinfo *F > {
	fi_name = F->f_name == NULL ? "<none>" :
	    basename(wstringof(F->f_name));
	fi_dirname = F->f_name == NULL ? "<none>" :
	    dirname(wstringof(F->f_name));
	fi_pathname = F->f_name == NULL ? "<none>" :
	    wstringof(F->f_name);
	fi_offset = F->f_offset;
	fi_fs = "?";
	fi_mount = "?";
	fi_oflags = F->f_ioflags;
	fi_cflags = F->f_createopt;
	fi_aflags = F->f_fileattrib;
	fi_sflags = F->f_shareflags;
	fi_bcount = F->f_iosize;
	fi_extinfo = F->f_extinfo;
	fi_rstatus = F->f_ntstatus;
	fi_dbuflen = F->f_dlen;
	fi_irp = F->f_irpptr;
	fi_dpattern = wstringof(F->f_dpattspec);
};

/* irp flags */
inline int IRP_NOCACHE = 0x1;
#pragma D binding "1.0" IRP_NOCACHE
inline int IRP_PAGING_IO = 0x2;
#pragma D binding "1.0" IRP_PAGING_IO
inline int IRP_MOUNT_COMPLETION = 0x2;
#pragma D binding "1.0" IRP_MOUNT_COMPLETION
inline int IRP_SYNCHRONOUS_API = 0x4;
#pragma D binding "1.0" IRP_SYNCHRONOUS_API
inline int IRP_ASSOCIATED_IRP = 0x8;
#pragma D binding "1.0" IRP_ASSOCIATED_IRP
inline int IRP_BUFFERED_IO = 0x10;
#pragma D binding "1.0" IRP_BUFFERED_IO
inline int IRP_DEALLOCATE_BUFFER = 0x20;
#pragma D binding "1.0" IRP_DEALLOCATE_BUFFER
inline int IRP_INPUT_OPERATION = 0x40;
#pragma D binding "1.0" IRP_INPUT_OPERATION
inline int IRP_SYNCHRONOUS_PAGING_IO = 0x40;
#pragma D binding "1.0" IRP_SYNCHRONOUS_PAGING_IO
inline int IRP_CREATE_OPERATION = 0x80;
#pragma D binding "1.0" IRP_CREATE_OPERATION
inline int IRP_READ_OPERATION = 0x100;
#pragma D binding "1.0" IRP_READ_OPERATION
inline int IRP_WRITE_OPERATION = 0x200;
#pragma D binding "1.0" IRP_WRITE_OPERATION
inline int IRP_CLOSE_OPERATION = 0x400;
#pragma D binding "1.0" IRP_CLOSE_OPERATION
inline int IRP_DEFER_IO_COMPLETION = 0x800;
#pragma D binding "1.0" IRP_DEFER_IO_COMPLETION
inline int IRP_OB_QUERY_NAME = 0x1000;
#pragma D binding "1.0" IRP_OB_QUERY_NAME
inline int IRP_HOLD_DEVICE_QUEUE = 0x2000;
#pragma D binding "1.0" IRP_HOLD_DEVICE_QUEUE
inline int IRP_RETRY_IO_COMPLETION = 0x4000;
#pragma D binding "1.0" IRP_RETRY_IO_COMPLETION

/* File ShareAccess flags */
inline int FILE_SHARE_READ = 0x00000001;
#pragma D binding "1.0" FILE_SHARE_READ
inline int FILE_SHARE_WRITE = 0x00000002;
#pragma D binding "1.0" FILE_SHARE_WRITE
inline int FILE_SHARE_DELETE = 0x00000004;
#pragma D binding "1.0" FILE_SHARE_DELETE
inline int FILE_SHARE_VALID_FLAGS = 0x00000007;
#pragma D binding "1.0" FILE_SHARE_VALID_FLAGS

/* File CreateDisposition flags */

inline int FILE_SUPERSEDE = 0x00000000;
#pragma D binding "1.0" FILE_SUPERSEDE
inline int FILE_OPEN = 0x00000001;
#pragma D binding "1.0" FILE_OPEN
inline int FILE_CREATE = 0x00000002;
#pragma D binding "1.0" FILE_CREATE
inline int FILE_OPEN_IF = 0x00000003;
#pragma D binding "1.0" FILE_OPEN_IF
inline int FILE_OVERWRITE = 0x00000004;
#pragma D binding "1.0" FILE_OVERWRITE
inline int FILE_OVERWRITE_IF = 0x00000005;
#pragma D binding "1.0" FILE_OVERWRITE_IF
inline int FILE_MAXIMUM_DISPOSITION = 0x00000005;
#pragma D binding "1.0" FILE_MAXIMUM_DISPOSITION

/* File CreateOptions  flags */

inline int FILE_DIRECTORY_FILE = 0x00000001;
#pragma D binding "1.0" FILE_DIRECTORY_FILE
inline int FILE_WRITE_THROUGH = 0x00000002;
#pragma D binding "1.0" FILE_WRITE_THROUGH
inline int FILE_SEQUENTIAL_ONLY = 0x00000004;
#pragma D binding "1.0" FILE_SEQUENTIAL_ONLY
inline int FILE_NO_INTERMEDIATE_BUFFERING = 0x00000008;
#pragma D binding "1.0" FILE_NO_INTERMEDIATE_BUFFERING
inline int FILE_SYNCHRONOUS_IO_ALERT = 0x00000010;
#pragma D binding "1.0" FILE_SYNCHRONOUS_IO_ALERT
inline int FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020;
#pragma D binding "1.0" FILE_SYNCHRONOUS_IO_NONALERT
inline int FILE_NON_DIRECTORY_FILE = 0x00000040;
#pragma D binding "1.0" FILE_NON_DIRECTORY_FILE
inline int FILE_CREATE_TREE_CONNECTION = 0x00000080;
#pragma D binding "1.0" FILE_CREATE_TREE_CONNECTION
inline int FILE_COMPLETE_IF_OPLOCKED = 0x00000100;
#pragma D binding "1.0" FILE_COMPLETE_IF_OPLOCKED
inline int FILE_NO_EA_KNOWLEDGE = 0x00000200;
#pragma D binding "1.0" FILE_NO_EA_KNOWLEDGE
inline int FILE_OPEN_FOR_RECOVERY = 0x00000400;
#pragma D binding "1.0" FILE_OPEN_FOR_RECOVERY
inline int FILE_RANDOM_ACCESS = 0x00000800;
#pragma D binding "1.0" FILE_RANDOM_ACCESS
inline int FILE_DELETE_ON_CLOSE = 0x00001000;
#pragma D binding "1.0" FILE_DELETE_ON_CLOSE
inline int FILE_OPEN_BY_FILE_ID = 0x00002000;
#pragma D binding "1.0" FILE_OPEN_BY_FILE_ID
inline int FILE_OPEN_FOR_BACKUP_INTENT = 0x00004000;
#pragma D binding "1.0" FILE_OPEN_FOR_BACKUP_INTENT
inline int FILE_NO_COMPRESSION = 0x00008000;
#pragma D binding "1.0" FILE_NO_COMPRESSION
inline int FILE_RESERVE_OPFILTER = 0x00100000;
#pragma D binding "1.0" FILE_RESERVE_OPFILTER
inline int FILE_OPEN_REPARSE_POINT = 0x00200000;
#pragma D binding "1.0" FILE_OPEN_REPARSE_POINT
inline int FILE_OPEN_NO_RECALL = 0x00400000;
#pragma D binding "1.0" FILE_OPEN_NO_RECALL
inline int FILE_OPEN_FOR_FREE_SPACE_QUERY = 0x00800000;
#pragma D binding "1.0" FILE_OPEN_FOR_FREE_SPACE_QUERY

/* File Attributes */

inline int FILE_ATTRIBUTE_READONLY = 0x00000001;
#pragma D binding "1.0" FILE_ATTRIBUTE_READONLY
inline int FILE_ATTRIBUTE_HIDDEN = 0x00000002;
#pragma D binding "1.0" FILE_ATTRIBUTE_HIDDEN
inline int FILE_ATTRIBUTE_SYSTEM = 0x00000004;
#pragma D binding "1.0" FILE_ATTRIBUTE_SYSTEM
inline int FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
#pragma D binding "1.0" FILE_ATTRIBUTE_DIRECTORY
inline int FILE_ATTRIBUTE_ARCHIVE = 0x00000020;
#pragma D binding "1.0" FILE_ATTRIBUTE_ARCHIVE
inline int FILE_ATTRIBUTE_DEVICE = 0x00000040;
#pragma D binding "1.0" FILE_ATTRIBUTE_DEVICE
inline int FILE_ATTRIBUTE_NORMAL = 0x00000080;
#pragma D binding "1.0" FILE_ATTRIBUTE_NORMAL
inline int FILE_ATTRIBUTE_TEMPORARY = 0x00000100;
#pragma D binding "1.0" FILE_ATTRIBUTE_TEMPORARY
inline int FILE_ATTRIBUTE_SPARSE_FILE = 0x00000200;
#pragma D binding "1.0" FILE_ATTRIBUTE_SPARSE_FILE
inline int FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;
#pragma D binding "1.0" FILE_ATTRIBUTE_REPARSE_POINT
inline int FILE_ATTRIBUTE_COMPRESSED = 0x00000800;
#pragma D binding "1.0" FILE_ATTRIBUTE_COMPRESSED
inline int FILE_ATTRIBUTE_OFFLINE = 0x00001000;
#pragma D binding "1.0" FILE_ATTRIBUTE_OFFLINE
inline int FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x00002000;
#pragma D binding "1.0" FILE_ATTRIBUTE_NOT_CONTENT_INDEXED
inline int FILE_ATTRIBUTE_ENCRYPTED = 0x00004000;
#pragma D binding "1.0" FILE_ATTRIBUTE_ENCRYPTED