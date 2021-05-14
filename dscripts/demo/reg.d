#pragma D option strsize=2048

reg:::create,
reg:::open,
reg:::delete,
reg:::query,
reg:::setvalue,
reg:::delvalue,
reg:::queryvalue,
reg:::enumkey,
reg:::enumvaluekey,
reg:::setinfo,
reg:::flush,
reg:::delvalue,
reg:::kcbcreate,
reg:::kcbdelete,
reg:::virtualize,
reg:::close
{
	printf("start io %s %s\n",probename, args[0]->r_rname);
}



/*
{ "MSNT_SystemTrace", "event", "create", &RegistryGuid, 10, sdt_etw_reg_cb, NULL, NULL, EVENT_TRACE_FLAG_REGISTRY },
	{ "MSNT_SystemTrace", "event", "open", &RegistryGuid, 11, sdt_etw_reg_cb, NULL, NULL, EVENT_TRACE_FLAG_REGISTRY },
	{ "MSNT_SystemTrace", "event", "delete", &RegistryGuid, 12, sdt_etw_reg_cb, NULL, NULL, EVENT_TRACE_FLAG_REGISTRY },
	{ "MSNT_SystemTrace", "event", "query", &RegistryGuid, 13, sdt_etw_reg_cb, NULL, NULL, EVENT_TRACE_FLAG_REGISTRY },
	{ "MSNT_SystemTrace", "event", "setvalue", &RegistryGuid, 14, sdt_etw_reg_cb, NULL, NULL, EVENT_TRACE_FLAG_REGISTRY },
	{ "MSNT_SystemTrace", "event", "delvalue", &RegistryGuid, 15, sdt_etw_reg_cb, NULL, NULL, EVENT_TRACE_FLAG_REGISTRY },
	{ "MSNT_SystemTrace", "event", "queryvalue", &RegistryGuid, 16, sdt_etw_reg_cb, NULL, NULL, EVENT_TRACE_FLAG_REGISTRY },
	{ "MSNT_SystemTrace", "event", "enumkey", &RegistryGuid, 17, sdt_etw_reg_cb, NULL, NULL, EVENT_TRACE_FLAG_REGISTRY },
	{ "MSNT_SystemTrace", "event", "enumvaluekey", &RegistryGuid, 18, sdt_etw_reg_cb, NULL, NULL, EVENT_TRACE_FLAG_REGISTRY },
	{ "MSNT_SystemTrace", "event", "querymulvalue", &RegistryGuid, 19, sdt_etw_reg_cb, NULL, NULL, EVENT_TRACE_FLAG_REGISTRY },
	{ "MSNT_SystemTrace", "event", "setinfo", &RegistryGuid, 20, sdt_etw_reg_cb, NULL, NULL, EVENT_TRACE_FLAG_REGISTRY },
	{ "MSNT_SystemTrace", "event", "flush", &RegistryGuid, 21, sdt_etw_reg_cb, NULL, NULL, EVENT_TRACE_FLAG_REGISTRY },
	{ "MSNT_SystemTrace", "event", "kcbcreate", &RegistryGuid, 22, sdt_etw_reg_cb, NULL, NULL, EVENT_TRACE_FLAG_REGISTRY },
	{ "MSNT_SystemTrace", "event", "kcbdelete", &RegistryGuid, 23, sdt_etw_reg_cb, NULL, NULL, EVENT_TRACE_FLAG_REGISTRY },
	{ "MSNT_SystemTrace", "event", "virtualize", &RegistryGuid, 26, sdt_etw_reg_cb, NULL, NULL, EVENT_TRACE_FLAG_REGISTRY },
	{ "MSNT_SystemTrace", "event", "close", &RegistryGuid, 27, sdt_etw_reg_cb, NULL, NULL, EVENT_TRACE_FLAG_REGISTRY },
	{ NULL }
	*/