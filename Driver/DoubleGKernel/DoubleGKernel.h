#pragma once

#include <ntddk.h>
#include <wdf.h>
#include <aux_klib.h>
#include <ntstrsafe.h>

#define DGK_PROTOCOL_VERSION      0x00020000UL
#define DGK_DRIVER_VERSION_MAJOR  2UL
#define DGK_DRIVER_VERSION_MINOR  0UL
#define DGK_DRIVER_VERSION_PATCH  0UL

#define DGK_CAP_ENUM_LOADED_MODULES 0x00000001UL
#define DGK_MAX_MODULE_PATH          256UL
#define DGK_MAX_RECORDS_PER_CALL     224UL
#define DGK_MAX_MODULE_BUFFER        (2UL * 1024UL * 1024UL)
#define DGK_POOL_TAG                 'KGDD'

#define IOCTL_DGK_GET_VERSION \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_DATA)

#define IOCTL_DGK_ENUM_MODULES \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_READ_DATA)

typedef struct _DGK_VERSION_INFO
{
    ULONG StructSize;
    ULONG ProtocolVersion;
    ULONG DriverVersionMajor;
    ULONG DriverVersionMinor;
    ULONG DriverVersionPatch;
    ULONG Capabilities;
    ULONG MaxRecordsPerCall;
    ULONG Reserved;
} DGK_VERSION_INFO, *PDGK_VERSION_INFO;

typedef struct _DGK_ENUM_REQUEST
{
    ULONG StructSize;
    ULONG StartIndex;
    ULONG MaxRecords;
    ULONG Reserved;
} DGK_ENUM_REQUEST, *PDGK_ENUM_REQUEST;

typedef struct _DGK_MODULE_RECORD
{
    ULONG StructSize;
    ULONG ImageSize;
    ULONG Flags;
    ULONG PathLength;
    CHAR FullPath[DGK_MAX_MODULE_PATH];
} DGK_MODULE_RECORD, *PDGK_MODULE_RECORD;

typedef struct _DGK_ENUM_RESPONSE
{
    ULONG StructSize;
    ULONG ProtocolVersion;
    ULONG TotalModules;
    ULONG ReturnedModules;
    ULONG NextIndex;
    ULONG RecordSize;
    DGK_MODULE_RECORD Records[1];
} DGK_ENUM_RESPONSE, *PDGK_ENUM_RESPONSE;

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD DgEvtDriverUnload;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL DgEvtIoDeviceControl;

NTSTATUS
DgCreateControlDevice(
    _In_ WDFDRIVER Driver
    );

NTSTATUS
DgQueryLoadedModules(
    _Outptr_result_bytebuffer_(*BufferSize) PAUX_MODULE_EXTENDED_INFO* Modules,
    _Out_ PULONG BufferSize
    );

VOID
DgFreeLoadedModules(
    _In_opt_ PAUX_MODULE_EXTENDED_INFO Modules
    );
