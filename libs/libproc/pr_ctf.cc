#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shlwapi.h>
#define _NO_CVCONST_H
#include <dbghelp.h>
#include <pthread.h>
#include <dtrace_misc.h>
#include <dtrace.h>
#include <libpe.h>
#include <libctf.h>
#include <libproc.h>
#include "etw.h"
#include "libproc_win.h"
#include "common.h"

/* from dt_open.c */

typedef struct dt_intrinsic {
	const char *din_name;	/* string name of the intrinsic type */
	ctf_encoding_t din_data; /* integer or floating-point CTF encoding */
	uint_t din_kind;	/* CTF type kind to instantiate */
} dt_intrinsic_t;

typedef struct dt_typedef {
	const char *dty_src;	/* string name of typedef source type */
	const char *dty_dst;	/* string name of typedef destination type */
} dt_typedef_t;

typedef struct pctf_info {
	struct ps_prochandle *P;
	HANDLE h;
	uintptr_t base;
} pctf_info_t;

/*
 * Tables of ILP32 intrinsic integer and floating-point type templates to use
 * to populate the dynamic "C" CTF type container.
 */
static const dt_intrinsic_t _dtrace_intrinsics_32[] = {
	{ "void", { CTF_INT_SIGNED, 0, 0 }, CTF_K_INTEGER },
	{ "signed", { CTF_INT_SIGNED, 0, 32 }, CTF_K_INTEGER },
	{ "unsigned", { 0, 0, 32 }, CTF_K_INTEGER },
	{ "char", { CTF_INT_SIGNED | CTF_INT_CHAR, 0, 8 }, CTF_K_INTEGER },
	{ "short", { CTF_INT_SIGNED, 0, 16 }, CTF_K_INTEGER },
	{ "int", { CTF_INT_SIGNED, 0, 32 }, CTF_K_INTEGER },
	{ "long", { CTF_INT_SIGNED, 0, 32 }, CTF_K_INTEGER },
	{ "long long", { CTF_INT_SIGNED, 0, 64 }, CTF_K_INTEGER },
	{ "signed char", { CTF_INT_SIGNED | CTF_INT_CHAR, 0, 8 }, CTF_K_INTEGER },
	{ "signed short", { CTF_INT_SIGNED, 0, 16 }, CTF_K_INTEGER },
	{ "signed int", { CTF_INT_SIGNED, 0, 32 }, CTF_K_INTEGER },
	{ "signed long", { CTF_INT_SIGNED, 0, 32 }, CTF_K_INTEGER },
	{ "signed long long", { CTF_INT_SIGNED, 0, 64 }, CTF_K_INTEGER },
	{ "unsigned char", { CTF_INT_CHAR, 0, 8 }, CTF_K_INTEGER },
	{ "unsigned short", { 0, 0, 16 }, CTF_K_INTEGER },
	{ "unsigned int", { 0, 0, 32 }, CTF_K_INTEGER },
	{ "unsigned long", { 0, 0, 32 }, CTF_K_INTEGER },
	{ "unsigned long long", { 0, 0, 64 }, CTF_K_INTEGER },
	{ "_Bool", { CTF_INT_BOOL, 0, 8 }, CTF_K_INTEGER },
	{ "float", { CTF_FP_SINGLE, 0, 32 }, CTF_K_FLOAT },
	{ "double", { CTF_FP_DOUBLE, 0, 64 }, CTF_K_FLOAT },
	{ "long double", { CTF_FP_LDOUBLE, 0, 128 }, CTF_K_FLOAT },
	{ "float imaginary", { CTF_FP_IMAGRY, 0, 32 }, CTF_K_FLOAT },
	{ "double imaginary", { CTF_FP_DIMAGRY, 0, 64 }, CTF_K_FLOAT },
	{ "long double imaginary", { CTF_FP_LDIMAGRY, 0, 128 }, CTF_K_FLOAT },
	{ "float complex", { CTF_FP_CPLX, 0, 64 }, CTF_K_FLOAT },
	{ "double complex", { CTF_FP_DCPLX, 0, 128 }, CTF_K_FLOAT },
	{ "long double complex", { CTF_FP_LDCPLX, 0, 256 }, CTF_K_FLOAT },
	{ NULL, { 0, 0, 0 }, 0 }
};

/*
 * Tables of LP64 intrinsic integer and floating-point type templates to use
 * to populate the dynamic "C" CTF type container.
 */
static const dt_intrinsic_t _dtrace_intrinsics_64[] = {
	{ "void", { CTF_INT_SIGNED, 0, 0 }, CTF_K_INTEGER },
	{ "signed", { CTF_INT_SIGNED, 0, 32 }, CTF_K_INTEGER },
	{ "unsigned", { 0, 0, 32 }, CTF_K_INTEGER },
	{ "char", { CTF_INT_SIGNED | CTF_INT_CHAR, 0, 8 }, CTF_K_INTEGER },
	{ "short", { CTF_INT_SIGNED, 0, 16 }, CTF_K_INTEGER },
	{ "int", { CTF_INT_SIGNED, 0, 32 }, CTF_K_INTEGER },
	{ "long", { CTF_INT_SIGNED, 0, 64 }, CTF_K_INTEGER },
	{ "long long", { CTF_INT_SIGNED, 0, 64 }, CTF_K_INTEGER },
	{ "signed char", { CTF_INT_SIGNED | CTF_INT_CHAR, 0, 8 }, CTF_K_INTEGER },
	{ "signed short", { CTF_INT_SIGNED, 0, 16 }, CTF_K_INTEGER },
	{ "signed int", { CTF_INT_SIGNED, 0, 32 }, CTF_K_INTEGER },
	{ "signed long", { CTF_INT_SIGNED, 0, 64 }, CTF_K_INTEGER },
	{ "signed long long", { CTF_INT_SIGNED, 0, 64 }, CTF_K_INTEGER },
	{ "unsigned char", { CTF_INT_CHAR, 0, 8 }, CTF_K_INTEGER },
	{ "unsigned short", { 0, 0, 16 }, CTF_K_INTEGER },
	{ "unsigned int", { 0, 0, 32 }, CTF_K_INTEGER },
	{ "unsigned long", { 0, 0, 64 }, CTF_K_INTEGER },
	{ "unsigned long long", { 0, 0, 64 }, CTF_K_INTEGER },
	{ "_Bool", { CTF_INT_BOOL, 0, 8 }, CTF_K_INTEGER },
	{ "float", { CTF_FP_SINGLE, 0, 32 }, CTF_K_FLOAT },
	{ "double", { CTF_FP_DOUBLE, 0, 64 }, CTF_K_FLOAT },
	{ "long double", { CTF_FP_LDOUBLE, 0, 128 }, CTF_K_FLOAT },
	{ "float imaginary", { CTF_FP_IMAGRY, 0, 32 }, CTF_K_FLOAT },
	{ "double imaginary", { CTF_FP_DIMAGRY, 0, 64 }, CTF_K_FLOAT },
	{ "long double imaginary", { CTF_FP_LDIMAGRY, 0, 128 }, CTF_K_FLOAT },
	{ "float complex", { CTF_FP_CPLX, 0, 64 }, CTF_K_FLOAT },
	{ "double complex", { CTF_FP_DCPLX, 0, 128 }, CTF_K_FLOAT },
	{ "long double complex", { CTF_FP_LDCPLX, 0, 256 }, CTF_K_FLOAT },
	{ NULL, { 0, 0, 0 }, 0 }
};


ctf_file_t *
init_ctf(struct ps_prochandle *P)
{
	ctf_file_t *fp;
	ctf_id_t id;
	const dt_intrinsic_t *dinp;
	int errp, err;
	pctf_info *info;

	if ((fp = ctf_create(&errp)) == NULL)
		return (NULL);

	if (P->model == PR_MODEL_ILP32) {
		dinp = _dtrace_intrinsics_32;
		ctf_setmodel(fp, CTF_MODEL_ILP32);
	} else {
		dinp = _dtrace_intrinsics_64;
		ctf_setmodel(fp, CTF_MODEL_LP64);
	}

	for (; dinp->din_name != NULL; dinp++) {
		if (dinp->din_kind == CTF_K_INTEGER) {
			err = ctf_add_integer(fp, CTF_ADD_ROOT,
			    dinp->din_name, &dinp->din_data);
		} else {
			err = ctf_add_float(fp, CTF_ADD_ROOT,
			    dinp->din_name, &dinp->din_data);
		}

		if (err == CTF_ERR) {
			return (NULL);
		}
	}

	(void) ctf_add_pointer(fp, CTF_ADD_ROOT,
	    ctf_lookup_by_name(fp, "void"));

	(void) ctf_add_pointer(fp, CTF_ADD_ROOT,
	    ctf_lookup_by_name(fp, "char"));

	(void) ctf_add_pointer(fp, CTF_ADD_ROOT,
	    ctf_lookup_by_name(fp, "int"));

	info = (pctf_info *) malloc(sizeof(pctf_info));
	info->P = P;
	info->h = P->phandle;
	info->base = 0;

	ctf_setosspecific(fp, info);
	if (ctf_update(fp) != 0) {
		free(info);
		return (NULL);
	}
	return (fp);
}

/* http://www.debuginfo.com/articles/dbghelptypeinfo.html */

enum BasicType {
	btNoType   = 0,
	btVoid     = 1,
	btChar     = 2,
	btWChar    = 3,
	btInt      = 6,
	btUInt     = 7,
	btFloat    = 8,
	btBCD      = 9,
	btBool     = 10,
	btLong     = 13,
	btULong    = 14,
	btCurrency = 25,
	btDate     = 26,
	btVariant  = 27,
	btComplex  = 28,
	btBit      = 29,
	btBSTR     = 30,
	btHresult  = 31
};


enum UdtKind {
	UdtStruct,
	UdtClass,
	UdtUnion
};

static ctf_id_t
ctf_process_tag(ctf_file_t *fp, DWORD type, DWORD tag, HANDLE h, DWORD64 base);
static ctf_id_t
ctf_dump_function(ctf_file_t *fp, DWORD type, DWORD tag,
    HANDLE h, DWORD64 base);

static ctf_id_t
ctf_basetype(ctf_file_t *fp, DWORD type, ULONG64 len)
{
	char *s;

	switch(type) {
	case btNoType:
		s = "void";
		break;
	case btVoid:
		s = "void ";
		break;
	case btChar:
		s = "char ";
		break;
	case btWChar:
		s = "unsigned short";
		break;
	case btInt:
		switch(len) {
		case 1:
			s = "char";
			break;
		case 2:
			s = "short";
			break;
		case 4:
			s = "int";
			break;
		default:
			s = "int";
			break;
		}
		break;
	case btUInt:
		switch(len) {
		case 1:
			s = "unsigned char";
			break;
		case 2:
			s = "unsigned short";
			break;
		case 4:
			s = "unsigned int";
			break;
		default:
			s = "unsigned int";
			break;
		}
		break;
	case btFloat:
		if (len == 4)
			s = "float";
		else if (len == 8)
			s = "double";
		else
			s = "double";
		break;
	case btBCD:
		s = "BCD";
		break;
	case btBool:
		s = "bool";
		break;
	case btLong:
		s = "long";
		break;
	case btULong:
		s = "unsigned long";
		break;
	case btCurrency:
	case btDate:
	case btVariant:
	case btComplex:
	case btBit:
	case btBSTR:
	case btHresult:
	default:
		s = "";
	}

	return (ctf_lookup_by_name(fp, s));
}


static
int
ctf_process_struct(ctf_file_t *fp, ctf_id_t souid, DWORD type, HANDLE h,
    DWORD64 base)
{
	DWORD count, tag, off, symid;
	ULONG64 length;
	TI_FINDCHILDREN_PARAMS *args;
	int i;
	wchar_t *name;
	char cname[MAX_SYM_NAME];
	ctf_id_t id;
	char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(char)];
	PSYMBOL_INFO sym = (PSYMBOL_INFO)buffer;

	sym->SizeOfStruct = sizeof(SYMBOL_INFO);
	sym->MaxNameLen = MAX_SYM_NAME;

	if (SymGetTypeInfo(h, base, type, TI_GET_CHILDRENCOUNT, &count) == 0)
		return (-1);

	// _ACTIVATION_CONTEXT_DATA
	if (count == 0)
		return (0);
		
	args = (TI_FINDCHILDREN_PARAMS *)
	    malloc(sizeof(TI_FINDCHILDREN_PARAMS) + sizeof(ULONG) * (count - 1));
	if (args == NULL)
		return -1;

	args->Count = count;
	args->Start = 0;
	if (SymGetTypeInfo(h, base, type, TI_FINDCHILDREN, args) == 0)
		return (-1);

	for (i = 0; i < count; i++) {
		if (SymGetTypeInfo(h, base, args->ChildId[i], TI_GET_SYMTAG, &tag) == 0)
			return (-1);

		if (tag != SymTagData) {
			return (-1);
		}
		if (SymGetTypeInfo(h, base, args->ChildId[i], TI_GET_SYMNAME, &name) == 0)
			return (-1);
		if (SymGetTypeInfo(h, base, args->ChildId[i], TI_GET_OFFSET, &off) == 0)
			return (-1);
		if (SymGetTypeInfo(h, base, args->ChildId[i], TI_GET_TYPEID, &type) == 0)
			return (-1);
		if (SymGetTypeInfo(h, base, type, TI_GET_SYMTAG, &tag) == 0)
			return (-1);
		id = ctf_process_tag(fp, type, tag, h, base);
		wcstombs(cname, name, MAX_SYM_NAME);
		if (ctf_add_member(fp, souid, cname, id) == CTF_ERR)
			return (-1);
	}
	return (0);
}

static ctf_id_t
lookup_type(ctf_file_t *fp, char *name, int type)
{
	char tname[MAX_SYM_NAME] = {0};

	switch (type) {
	case UdtStruct:
		strncpy(tname, "struct ", 7);
		strcpy(&tname[7], name);
		break;
	case UdtUnion:
		strncpy(tname, "union ", 6);
		strcpy(&tname[6], name);
		break;
	default:
		return (ctf_lookup_by_name(fp, name));
	}
	return (ctf_lookup_by_name(fp, tname));
}

static ctf_id_t
ctf_dump_udt(ctf_file_t *fp, DWORD type, DWORD tag, HANDLE h, DWORD64 base)
{
	DWORD itag, itype;
	wchar_t *name;
	DWORD64 size, off;
	DWORD kind;
	char cname[MAX_SYM_NAME];
	ctf_id_t souid;

	if (SymGetTypeInfo(h, base, type, TI_GET_LENGTH, &size) == 0)
		return (-1);
	if (SymGetTypeInfo(h, base, type, TI_GET_UDTKIND, &kind) == 0)
		return (-1);

	switch (kind) {
	case UdtStruct:
	case UdtUnion:
		if (SymGetTypeInfo(h, base, type, TI_GET_SYMNAME, &name) == 0)
			return (-1);
		wcstombs(cname, name, MAX_SYM_NAME);

		if ((souid = lookup_type(fp, cname, kind)) != CTF_ERR) {
			return (souid);
		}
		if (kind == UdtStruct) {
			if ((souid = ctf_add_struct(fp, 1, cname)) == CTF_ERR ||
			    ctf_update(fp) == CTF_ERR)
				return (-1);
		} else {
			if ((souid = ctf_add_union(fp, 1, cname)) == CTF_ERR ||
			    ctf_update(fp) == CTF_ERR)
				return (-1);
		}
		if (ctf_process_struct(fp, souid, type, h, base) == -1)
			return (-1);

		return (souid);
		
		break;
	case UdtClass:
		break;
	default:
		break;
	}
	
	return (-1);
}

static ctf_id_t
ctf_dump_array(ctf_file_t *fp, DWORD type, DWORD tag,
    HANDLE h, DWORD64 base)
{
	DWORD count, itype, itag;
	DWORD64 len;
	char st[100], d = 0;;
	ctf_arinfo_t ctr;

	if (SymGetTypeInfo(h, base, type, TI_GET_TYPEID, &itype) == 0)
		return (-1);
	if (SymGetTypeInfo(h, base, type, TI_GET_COUNT, &count) == 0)
		return (-1);
	if (SymGetTypeInfo(h, base, type, TI_GET_LENGTH, &len) == 0)
		return (-1);
	if (SymGetTypeInfo(h, base, itype, TI_GET_SYMTAG, &itag) == 0)
		return (-1);
	type = itype;
	if (itag == SymTagArrayType) {
		ctr.ctr_contents = ctf_dump_array(fp, itype, itag, h, base);
	} else {
		ctr.ctr_contents = ctf_process_tag(fp, itype, itag, h, base);
	}
	ctr.ctr_index = ctf_lookup_by_name(fp, "long");
	ctr.ctr_nelems = count;

	return (ctf_add_array(fp, CTF_ADD_ROOT, &ctr));
}

static ctf_id_t
ctf_dump_enum(ctf_file_t *fp, DWORD type, DWORD tag, HANDLE h, DWORD64 base)
{
	DWORD count, itype, itag;
	DWORD64 len;
	ctf_arinfo_t ctr;
	char cname[MAX_SYM_NAME];
	wchar_t *name;
	DWORD nested = 0;
	VARIANT var;
	TI_FINDCHILDREN_PARAMS *args;
	int i;
	ctf_id_t id = -1;

	if (SymGetTypeInfo(h, base, type, TI_GET_TYPEID, &itype) == 0)
		return (-1);
	if (SymGetTypeInfo(h, base, type, TI_GET_SYMNAME, &name) == 0)
		return (-1);

	wcstombs(cname, name, MAX_SYM_NAME);

	if ((id = ctf_add_enum(fp, CTF_ADD_ROOT, cname)) == CTF_ERR ||
	    ctf_update(fp) == CTF_ERR)
		return (-1);

	if (SymGetTypeInfo(h, base, type, TI_GET_NESTED, &nested) == 0)
		return (-1);

	if (SymGetTypeInfo(h, base, type, TI_GET_CHILDRENCOUNT, &count) == 0)
		return (-1);

	args = (TI_FINDCHILDREN_PARAMS *)
	    malloc(sizeof(TI_FINDCHILDREN_PARAMS) + sizeof(ULONG) * (count));
	if (args == NULL)
		return (-1);

	args->Count = count;
	args->Start = 0;
	if (SymGetTypeInfo(h, base, type, TI_FINDCHILDREN, args) == 0)
		return (-1);

	for (i = 0; i < count; i++)	{
		if (SymGetTypeInfo(h, base, args->ChildId[i], TI_GET_SYMTAG, &itag) == 0)
			return (-1);
		if (itag == SymTagData) {
			if (SymGetTypeInfo(h, base, args->ChildId[i], TI_GET_SYMNAME, &name) == 0)
				return (-1);
			wcstombs(cname, name, MAX_SYM_NAME);
			if (SymGetTypeInfo(h, base, args->ChildId[i], TI_GET_VALUE, &var) == 0)
				return (-1);
			if (ctf_add_enumerator(fp, id, cname, var.iVal) == CTF_ERR)
				return (-1);
		}
	}

	if (ctf_update(fp) == CTF_ERR)
		return (-1);

	return (id);
}

static ctf_id_t
ctf_process_tag(ctf_file_t *fp, DWORD type, DWORD tag,
    HANDLE h, DWORD64 base)
{
	ULONG64 length;
	DWORD itype, itag, udtkind;
	wchar_t *name;
	char cname[MAX_SYM_NAME];
	ctf_id_t id, ptr;

	switch(tag) {
	case SymTagBaseType:
		if (SymGetTypeInfo(h, base, type, TI_GET_BASETYPE, &itag) == 0)
			return (-1);
		if (SymGetTypeInfo(h, base, type, TI_GET_LENGTH, &length) == 0)
			return (-1);

		return (ctf_basetype(fp, itag, length));

		break;
	case SymTagPointerType:
		if (SymGetTypeInfo(h, base, type, TI_GET_TYPEID, &itype) == 0)
			return (-1);
		if (SymGetTypeInfo(h, base, type, TI_GET_LENGTH, &length) == 0)
			return (-1);
		if (SymGetTypeInfo(h, base, itype, TI_GET_SYMTAG, &itag) == 0)
			return (-1);
		if ((id = ctf_process_tag(fp, itype, itag, h, base)) == -1)
			return (-1);

		ptr =  ctf_add_pointer(fp, CTF_ADD_ROOT, id);
		if (ptr == CTF_ERR || ctf_update(fp) == CTF_ERR)
			return (-1);
		return (ptr);
		break;
	case SymTagUDT:
		if ((ptr = ctf_dump_udt(fp, type, tag, h, base)) == -1)
			return (-1);
		return ptr;
		break;
	case SymTagTypedef:
		if (SymGetTypeInfo(h, base, type, TI_GET_TYPEID, &itype) == 0)
			return (-1);
		if (SymGetTypeInfo(h, base, itype, TI_GET_SYMTAG, &itag) == 0)
			return (-1);
		id = ctf_process_tag(fp, itype, itag, h, base);
		if (SymGetTypeInfo(h, base, type, TI_GET_SYMNAME, &name) == 0)
			return (-1);
		wcstombs(cname, name, MAX_SYM_NAME);
		ptr = ctf_add_typedef(fp, CTF_ADD_ROOT, cname, id);
		if (ptr == CTF_ERR || ctf_update(fp) == CTF_ERR)
			return (-1);
		return (ptr);

		break;
	case SymTagArrayType:
		ptr = ctf_dump_array(fp, type, tag, h, base);
		if (ptr == CTF_ERR || ctf_update(fp) == CTF_ERR)
			return (-1);
		return (ptr);
	case SymTagFunctionType:
		ptr = ctf_dump_function(fp, type, tag, h, base);
		if (ptr == CTF_ERR || ctf_update(fp) == CTF_ERR)
			return (-1);
		return (ptr);

	case SymTagEnum:
		ptr = ctf_dump_enum(fp, type, tag, h, base);
		if (ptr == CTF_ERR || ctf_update(fp) == CTF_ERR)
			return (-1);
		return (ptr);

	default:
		ASSERT(0);
	}

	return (-1);
}

static ctf_id_t
ctf_win_func_ret(ctf_file_t *fp, ULONG typeindex, HANDLE h, DWORD64 base)
{
	DWORD tag, itag, itype;

	if (SymGetTypeInfo(h, base, typeindex, TI_GET_SYMTAG, &tag) == 0)
		return (-1);

	if (tag != SymTagFunctionType)
		return (-1);

	if (SymGetTypeInfo(h, base, typeindex, TI_GET_TYPEID, &itype) == 0)
		return (-1);
	if (SymGetTypeInfo(h, base, itype, TI_GET_SYMTAG, &itag) == 0)
		return (-1);

	return (ctf_process_tag(fp, itype, itag, h, base));
}

static int
ctf_win_func_arg_count(ctf_file_t *fp, ULONG typeindex, HANDLE h, DWORD64 base)
{
	DWORD tag, itag, count;

	if (SymGetTypeInfo(h, base, typeindex, TI_GET_CHILDRENCOUNT, &count) == 0)
		return (-1);

	return (count);
}

static int
ctf_win_func_args(ctf_file_t *fp, ULONG typeindex, uint_t argc,
    ctf_id_t *argv, HANDLE h, DWORD64 base)
{
	DWORD tag, type, count;
	ULONG64 length;
	TI_FINDCHILDREN_PARAMS *args;
	int i;
	ctf_id_t id;

	if (SymGetTypeInfo(h, base, typeindex, TI_GET_CHILDRENCOUNT, &count) == 0)
		return (-1);
	args = (TI_FINDCHILDREN_PARAMS *)
	    malloc(sizeof(TI_FINDCHILDREN_PARAMS) + sizeof(ULONG) * (count - 1));
	if (args == NULL)
		return (-1);

	args->Count = count;
	args->Start = 0;
	if (SymGetTypeInfo(h, base, typeindex, TI_FINDCHILDREN, args) == 0)
		return (-1);
	count = MIN(argc, count);

	for (i = 0; i < count; i++) {
		if (SymGetTypeInfo(h, base, args->ChildId[i], TI_GET_SYMTAG, &tag) == 0)
			return 0;

		if (tag != SymTagFunctionArgType) {
			ASSERT(0);
			return (-1);
		}

		if (SymGetTypeInfo(h, base, args->ChildId[i], TI_GET_TYPEID, &type) == 0)
			return (-1);
		if (SymGetTypeInfo(h, base, type, TI_GET_SYMTAG, &tag) == 0)
			return (-1);
		if ((id = ctf_process_tag(fp, type, tag, h, base)) == -1)
			return (-1);
		*argv++ = id;
	}
	return (0);
}

static ctf_id_t
ctf_dump_function(ctf_file_t *fp, DWORD type, DWORD tag,
    HANDLE h, DWORD64 base)
{
	ctf_id_t id, ret = ctf_win_func_ret(fp, type, h, base);
	int count = ctf_win_func_arg_count(fp, type, h, base);
	ctf_funcinfo_t ctc;
	ctf_id_t *argv = NULL;

	ctc.ctc_return = ret;
	ctc.ctc_argc = count;

	if (count > 0) {
		argv = (ctf_id_t *) malloc(sizeof(ctf_id_t) * count);
		if (argv == NULL)
			count = 0;
		else if (ctf_win_func_args(fp, type, count, argv, h, base) == -1 ||
		    ctf_update(fp) == CTF_ERR) {
			count = 0;
			free(argv);
			argv = NULL;
		}
	}
	ctc.ctc_flags = 0;
	
	id = ctf_add_function(fp, CTF_ADD_ROOT, &ctc, argv);
	if (argv)
		free(argv);

	return (id);
}

int
pr_ctf_func_info(ctf_file_t *fp, ulong_t symidx, ctf_funcinfo_t *fip)
{
	HANDLE handle = 0;
	DWORD64 base = 0;
	char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(char)];
	PSYMBOL_INFO sym = (PSYMBOL_INFO)buffer;
	ctf_id_t ret;
	int count;
	pctf_info *cinfo = (pctf_info *) ctf_getosspecific(fp);

	handle = cinfo->P->phandle;
	base = cinfo->base;

	sym->SizeOfStruct = sizeof(SYMBOL_INFO);
	sym->MaxNameLen = MAX_SYM_NAME;

	if (SymFromIndex(handle, base, symidx, sym) == FALSE)
		return (-1);
	if (sym->Tag != SymTagFunction)
		return (-1);

	if ((ret = ctf_win_func_ret(fp, sym->TypeIndex, handle, base)) == -1)
		return (-1);

	if ((count = ctf_win_func_arg_count(fp, sym->TypeIndex, handle, base)) == -1)
		return (-1);

	if (ctf_update(fp) == CTF_ERR)
		return (-1);

	fip->ctc_return = ret;
	fip->ctc_argc = count;
	fip->ctc_flags = 0;

	return (0);
}

int
pr_ctf_func_args(ctf_file_t *fp,
    ulong_t symidx, uint_t argc, ctf_id_t *argv)
{
	HANDLE h = 0;
	DWORD64 base = 0;
	char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(char)];
	PSYMBOL_INFO sym = (PSYMBOL_INFO)buffer;
	pctf_info *cinfo = (pctf_info *) ctf_getosspecific(fp);

	h = cinfo->P->phandle;
	base = cinfo->base;

	sym->SizeOfStruct = sizeof(SYMBOL_INFO);
	sym->MaxNameLen = MAX_SYM_NAME;

	if (SymFromIndex(h, base, symidx, sym) == FALSE)
		return (-1);
	if (sym->Tag != SymTagFunction)
		return (-1);
	if  (ctf_win_func_args(fp, sym->TypeIndex, argc, argv, h, base) == -1)
		return (-1);
	if (ctf_update(fp) == CTF_ERR)
		return (-1);

	return (0);
}

ctf_file_t *
pr_name_to_ctf(struct ps_prochandle * P, proc_mod_t *mod)
{
	ctf_file_t *fp;
	ctf_id_t id;
	int errp, err;
	pctf_info *info, *tmp;

	if (mod->c_ctf != NULL)
		return ((ctf_file_t *) mod->c_ctf);

	if (P->p_ctf == NULL) {
		if ((P->p_ctf = init_ctf(P)) == NULL)
			return (NULL);
	}

	if ((fp = ctf_create(&errp)) == NULL)
		return (NULL);

	if (P->model == PR_MODEL_ILP32) {
		ctf_setmodel(fp, CTF_MODEL_ILP32);
	} else {
		ctf_setmodel(fp, CTF_MODEL_LP64);
	}
	info = (pctf_info *) malloc(sizeof(pctf_info));
	if (info == NULL)
		return (NULL);

	info->base = mod->imgbase;
	info->h = P->phandle;
	info->P = P;

	ctf_setosspecific(fp, info);

	if (ctf_import(fp, P->p_ctf) == CTF_ERR) {
		return (NULL);
	}

	if (ctf_update(fp) != 0) {
		return (NULL);
	}
	tmp = (pctf_info *) ctf_getspecific(fp);
	mod->c_ctf = fp;

	return (fp);
}

typedef struct pctf_type {
	ctf_id_t id;
	pctf_info *cinfo;
	ctf_file_t *fp;
} pctf_type_t;

BOOL CALLBACK SymEnumTypesProc(PSYMBOL_INFO s, ULONG SymbolSize,
    PVOID UserContext);

BOOL CALLBACK
SymEnumTypesProc(PSYMBOL_INFO s, ULONG SymbolSize,
    PVOID UserContext)
{
	pctf_type_t *tinfo = (pctf_type_t *) UserContext;
	HANDLE h = 0;
	DWORD64 base = 0;
	ctf_file_t *fp;

	h = tinfo->cinfo->P->phandle;
	base = tinfo->cinfo->base;
	fp = tinfo->fp;

	if (s == NULL)
		return (TRUE);

	tinfo->id = ctf_process_tag(fp, s->TypeIndex, s->Tag, h, base);

	return (TRUE);
}

ctf_id_t
pr_ctf_lookup_by_name(ctf_file_t *fp, const char *name)
{
	HANDLE h = 0;
	DWORD64 base = 0;
	pctf_info *cinfo;
	ctf_id_t id = -1;
	pctf_type_t tinfo = {0};

	if ((id = ctf_lookup_by_name(fp, name)) != CTF_ERR)
		return (id);

	cinfo = (pctf_info *) ctf_getosspecific(fp);
	if (cinfo == NULL)
		return (-1);

	h = cinfo->P->phandle;
	base = cinfo->base;
	tinfo.cinfo = cinfo;
	tinfo.fp = fp;
	tinfo.id = -1;

	if (SymEnumTypesByName(h, base, name, SymEnumTypesProc, &tinfo) == FALSE) {
		return (-1);
	}
	if (ctf_update(fp) != 0)
		return (-1);

	return (tinfo.id);
}