#include "DoubleGKernel.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, DgCreateControlDevice)
#pragma alloc_text(PAGE, DgQueryLoadedModules)
#pragma alloc_text(PAGE, DgFreeLoadedModules)
#endif

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    WDF_DRIVER_CONFIG configuration;
    WDFDRIVER driver = NULL;
    NTSTATUS status;

    WDF_DRIVER_CONFIG_INIT(
        &configuration,
        WDF_NO_EVENT_CALLBACK
        );

    configuration.EvtDriverUnload = DgEvtDriverUnload;

    status = WdfDriverCreate(
        DriverObject,
        RegistryPath,
        WDF_NO_OBJECT_ATTRIBUTES,
        &configuration,
        &driver
        );

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = AuxKlibInitialize();

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    return DgCreateControlDevice(driver);
}

NTSTATUS
DgCreateControlDevice(
    _In_ WDFDRIVER Driver
    )
{
    DECLARE_CONST_UNICODE_STRING(
        deviceName,
        L"\\Device\\DoubleGKernel"
        );

    DECLARE_CONST_UNICODE_STRING(
        symbolicLink,
        L"\\DosDevices\\DoubleGKernel"
        );

    // SYSTEM receives full access. Built-in Administrators receive read access.
    // Normal users cannot open the control device.
    DECLARE_CONST_UNICODE_STRING(
        securityDescriptor,
        L"D:P(A;;GA;;;SY)(A;;GR;;;BA)"
        );

    PWDFDEVICE_INIT deviceInit = NULL;
    WDF_OBJECT_ATTRIBUTES deviceAttributes;
    WDF_IO_QUEUE_CONFIG queueConfiguration;
    WDFDEVICE device = NULL;
    NTSTATUS status;

    PAGED_CODE();

    deviceInit = WdfControlDeviceInitAllocate(
        Driver,
        &securityDescriptor
        );

    if (deviceInit == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    WdfDeviceInitSetExclusive(deviceInit, FALSE);
    WdfDeviceInitSetIoType(deviceInit, WdfDeviceIoBuffered);

    status = WdfDeviceInitAssignName(
        deviceInit,
        &deviceName
        );

    if (!NT_SUCCESS(status))
    {
        WdfDeviceInitFree(deviceInit);
        return status;
    }

    WDF_OBJECT_ATTRIBUTES_INIT(&deviceAttributes);
    deviceAttributes.ExecutionLevel = WdfExecutionLevelPassive;

    status = WdfDeviceCreate(
        &deviceInit,
        &deviceAttributes,
        &device
        );

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(
        &queueConfiguration,
        WdfIoQueueDispatchParallel
        );

    queueConfiguration.EvtIoDeviceControl =
        DgEvtIoDeviceControl;

    status = WdfIoQueueCreate(
        device,
        &queueConfiguration,
        WDF_NO_OBJECT_ATTRIBUTES,
        WDF_NO_HANDLE
        );

    if (!NT_SUCCESS(status))
    {
        WdfObjectDelete(device);
        return status;
    }

    status = WdfDeviceCreateSymbolicLink(
        device,
        &symbolicLink
        );

    if (!NT_SUCCESS(status))
    {
        WdfObjectDelete(device);
        return status;
    }

    WdfControlFinishInitializing(device);

    return STATUS_SUCCESS;
}

VOID
DgEvtDriverUnload(
    _In_ WDFDRIVER Driver
    )
{
    UNREFERENCED_PARAMETER(Driver);
}

VOID
DgEvtIoDeviceControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode
    )
{
    UNREFERENCED_PARAMETER(Queue);

    PIRP irp = WdfRequestWdmGetIrp(Request);
    NTSTATUS status = IoValidateDeviceIoControlAccess(
        irp,
        FILE_READ_ACCESS
        );

    if (!NT_SUCCESS(status))
    {
        WdfRequestComplete(Request, status);
        return;
    }

    if (IoControlCode == IOCTL_DGK_GET_VERSION)
    {
        PDGK_VERSION_INFO output = NULL;
        size_t outputLength = 0;

        status = WdfRequestRetrieveOutputBuffer(
            Request,
            sizeof(DGK_VERSION_INFO),
            (PVOID*)&output,
            &outputLength
            );

        if (!NT_SUCCESS(status))
        {
            WdfRequestComplete(Request, status);
            return;
        }

        RtlZeroMemory(output, outputLength);

        output->StructSize = sizeof(DGK_VERSION_INFO);
        output->ProtocolVersion = DGK_PROTOCOL_VERSION;
        output->DriverVersionMajor = DGK_DRIVER_VERSION_MAJOR;
        output->DriverVersionMinor = DGK_DRIVER_VERSION_MINOR;
        output->DriverVersionPatch = DGK_DRIVER_VERSION_PATCH;
        output->Capabilities = DGK_CAP_ENUM_LOADED_MODULES;
        output->MaxRecordsPerCall = DGK_MAX_RECORDS_PER_CALL;

        WdfRequestCompleteWithInformation(
            Request,
            STATUS_SUCCESS,
            sizeof(DGK_VERSION_INFO)
            );

        return;
    }

    if (IoControlCode == IOCTL_DGK_ENUM_MODULES)
    {
        PDGK_ENUM_REQUEST input = NULL;
        PDGK_ENUM_RESPONSE output = NULL;
        size_t inputLength = 0;
        size_t outputLength = 0;
        PAUX_MODULE_EXTENDED_INFO modules = NULL;
        ULONG modulesSize = 0;

        status = WdfRequestRetrieveInputBuffer(
            Request,
            sizeof(DGK_ENUM_REQUEST),
            (PVOID*)&input,
            &inputLength
            );

        if (!NT_SUCCESS(status))
        {
            WdfRequestComplete(Request, status);
            return;
        }

        if (input->StructSize != sizeof(DGK_ENUM_REQUEST))
        {
            WdfRequestComplete(Request, STATUS_INVALID_PARAMETER);
            return;
        }

        status = WdfRequestRetrieveOutputBuffer(
            Request,
            FIELD_OFFSET(DGK_ENUM_RESPONSE, Records),
            (PVOID*)&output,
            &outputLength
            );

        if (!NT_SUCCESS(status))
        {
            WdfRequestComplete(Request, status);
            return;
        }

        RtlZeroMemory(output, outputLength);

        status = DgQueryLoadedModules(
            &modules,
            &modulesSize
            );

        if (!NT_SUCCESS(status))
        {
            WdfRequestComplete(Request, status);
            return;
        }

        ULONG totalModules =
            modulesSize / sizeof(AUX_MODULE_EXTENDED_INFO);

        ULONG headerSize =
            FIELD_OFFSET(DGK_ENUM_RESPONSE, Records);

        ULONG outputCapacity =
            outputLength <= headerSize
                ? 0
                : (ULONG)((outputLength - headerSize) /
                    sizeof(DGK_MODULE_RECORD));

        ULONG requestedRecords = input->MaxRecords;

        if (requestedRecords == 0 ||
            requestedRecords > DGK_MAX_RECORDS_PER_CALL)
        {
            requestedRecords = DGK_MAX_RECORDS_PER_CALL;
        }

        ULONG capacity = min(
            outputCapacity,
            requestedRecords
            );

        ULONG startIndex = min(
            input->StartIndex,
            totalModules
            );

        ULONG remaining = totalModules - startIndex;
        ULONG returned = min(capacity, remaining);

        output->StructSize = headerSize;
        output->ProtocolVersion = DGK_PROTOCOL_VERSION;
        output->TotalModules = totalModules;
        output->ReturnedModules = returned;
        output->NextIndex = startIndex + returned;
        output->RecordSize = sizeof(DGK_MODULE_RECORD);

        for (ULONG index = 0; index < returned; index++)
        {
            PAUX_MODULE_EXTENDED_INFO source =
                &modules[startIndex + index];

            PDGK_MODULE_RECORD destination =
                &output->Records[index];

            destination->StructSize =
                sizeof(DGK_MODULE_RECORD);

            destination->ImageSize =
                source->ImageSize;

            destination->Flags = 0;

            SIZE_T sourceLength = 0;

            while (
                sourceLength <
                    sizeof(source->FullPathName) &&
                source->FullPathName[sourceLength] != '\0'
                )
            {
                sourceLength++;
            }

            SIZE_T copyLength = min(
                sourceLength,
                (SIZE_T)DGK_MAX_MODULE_PATH - 1
                );

            if (copyLength > 0)
            {
                RtlCopyMemory(
                    destination->FullPath,
                    source->FullPathName,
                    copyLength
                    );
            }

            destination->FullPath[copyLength] = '\0';
            destination->PathLength = (ULONG)copyLength;
        }

        DgFreeLoadedModules(modules);

        size_t bytesReturned =
            headerSize +
            ((size_t)returned *
                sizeof(DGK_MODULE_RECORD));

        WdfRequestCompleteWithInformation(
            Request,
            STATUS_SUCCESS,
            bytesReturned
            );

        return;
    }

    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);

    WdfRequestComplete(
        Request,
        STATUS_INVALID_DEVICE_REQUEST
        );
}

NTSTATUS
DgQueryLoadedModules(
    _Outptr_result_bytebuffer_(*BufferSize) PAUX_MODULE_EXTENDED_INFO* Modules,
    _Out_ PULONG BufferSize
    )
{
    NTSTATUS status;
    ULONG requiredBytes = 0;
    PAUX_MODULE_EXTENDED_INFO buffer = NULL;

    PAGED_CODE();

    if (Modules == NULL ||
        BufferSize == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    *Modules = NULL;
    *BufferSize = 0;

    for (ULONG attempt = 0; attempt < 3; attempt++)
    {
        requiredBytes = 0;

        status = AuxKlibQueryModuleInformation(
            &requiredBytes,
            sizeof(AUX_MODULE_EXTENDED_INFO),
            NULL
            );

        if (!NT_SUCCESS(status))
        {
            return status;
        }

        if (requiredBytes == 0 ||
            requiredBytes > DGK_MAX_MODULE_BUFFER)
        {
            return STATUS_INVALID_BUFFER_SIZE;
        }

        buffer = (PAUX_MODULE_EXTENDED_INFO)
            ExAllocatePool2(
                POOL_FLAG_PAGED,
                requiredBytes,
                DGK_POOL_TAG
                );

        if (buffer == NULL)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlZeroMemory(buffer, requiredBytes);

        ULONG queryBytes = requiredBytes;

        status = AuxKlibQueryModuleInformation(
            &queryBytes,
            sizeof(AUX_MODULE_EXTENDED_INFO),
            buffer
            );

        if (status == STATUS_BUFFER_TOO_SMALL)
        {
            ExFreePoolWithTag(
                buffer,
                DGK_POOL_TAG
                );

            buffer = NULL;
            continue;
        }

        if (!NT_SUCCESS(status))
        {
            ExFreePoolWithTag(
                buffer,
                DGK_POOL_TAG
                );

            return status;
        }

        *Modules = buffer;
        *BufferSize = queryBytes;

        return STATUS_SUCCESS;
    }

    return STATUS_BUFFER_TOO_SMALL;
}

VOID
DgFreeLoadedModules(
    _In_opt_ PAUX_MODULE_EXTENDED_INFO Modules
    )
{
    PAGED_CODE();

    if (Modules != NULL)
    {
        ExFreePoolWithTag(
            Modules,
            DGK_POOL_TAG
            );
    }
}
