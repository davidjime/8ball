//*****************************************************************************
//
// Copyright (C) 2014 Texas Instruments Incorporated - http://www.ti.com/ 
// 
// 
//  Redistribution and use in source and binary forms, with or without 
//  modification, are permitted provided that the following conditions 
//  are met:
//
//    Redistributions of source code must retain the above copyright 
//    notice, this list of conditions and the following disclaimer.
//
//    Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the 
//    documentation and/or other materials provided with the   
//    distribution.
//
//    Neither the name of Texas Instruments Incorporated nor the names of
//    its contributors may be used to endorse or promote products derived
//    from this software without specific prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
//  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
//  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
//  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT 
//  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
//  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT 
//  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
//  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
//  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
//  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
//  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
//*****************************************************************************


//*****************************************************************************
//
// Application Name     -   SSL Demo
// Application Overview -   This is a sample application demonstrating the
//                          use of secure sockets on a CC3200 device.The
//                          application connects to an AP and
//                          tries to establish a secure connection to the
//                          Google server.
// Application Details  -
// docs\examples\CC32xx_SSL_Demo_Application.pdf
// or
// http://processors.wiki.ti.com/index.php/CC32xx_SSL_Demo_Application
//
//*****************************************************************************


//*****************************************************************************
//
//! \addtogroup ssl
//! @{
//
//*****************************************************************************

// Simplelink includes
#include "simplelink.h"

//Driverlib includes
#include "stdio.h"
#include "hw_memmap.h"
#include "hw_common_reg.h"
#include "hw_types.h"
#include "hw_ints.h"
#include "rom.h"
#include "rom_map.h"
#include "interrupt.h"
#include "prcm.h"
#include "utils.h"
#include "uart.h"
#include "gpio.h"
//Common interface includes
#include "pin_mux_config.h"
#include "gpio_if.h"
#include "common.h"
#include "uart_if.h"
#include "spi.h"
#include "Adafruit_GFX.h"
#include "Adafruit_SSD1351.h"
#include "i2c_if.h"
#include <string.h>

#define SPI_IF_BIT_RATE  100000
#define TR_BUFF_SIZE     100

#define MAX_URI_SIZE 128
#define URI_SIZE MAX_URI_SIZE + 1


#define APPLICATION_NAME        "SSL"
#define APPLICATION_VERSION     "1.1.1.EEC.Spring2020"
#define SERVER_NAME                "a2c3p5nk3ssxwr-ats.iot.us-east-1.amazonaws.com"
#define GOOGLE_DST_PORT             8443

#define SL_SSL_CA_CERT "/cert/rootCA.der"
#define SL_SSL_PRIVATE "/cert/private.der"
#define SL_SSL_CLIENT  "/cert/client.der"

//NEED TO UPDATE THIS FOR IT TO WORK!
#define DATE                18    /* Current Date */
#define MONTH               05     /* Month 1-12 */
#define YEAR                2020  /* Current year */
#define HOUR                13    /* Time - hours */
#define MINUTE              16    /* Time - minutes */
#define SECOND              0     /* Time - seconds */

#define POSTHEADER "POST /things/lab4thing/shadow HTTP/1.1\n\r"
#define HOSTHEADER "Host: a2c3p5nk3ssxwr-ats.iot.us-east-1.amazonaws.com\r\n"
#define CHEADER "Connection: Keep-Alive\r\n"
#define CTHEADER "Content-Type: application/json; charset=utf-8\r\n"
#define CLHEADER1 "Content-Length: "
#define CLHEADER2 "\r\n\r\n"

#define DATA1 "{\"state\": {\n\r\"desired\" : {\n\r\"messageagain\" : {\"default\": \"Sample fallback message\",\"sms\": \"Game Over!\"}\n\r}}}\n\r\n\r"
#define DATA2 "{\"state\": {\n\r\"desired\" : {\n\r\"messageagain\" : {\"default\": \"Sample fallback message\",\"sms\": \"Ball #N landed in Pocket M!\"}\n\r}}}\n\r\n\r"
#define BLACK           0x0000
#define BLUE            0x001F
#define GREEN           0x07E0
#define CYAN            0x07FF
#define RED             0xF800
#define MAGENTA         0xF81F
#define YELLOW          0xFFE0
#define WHITE           0xFFFF
#define FAILURE                 -1
#define SUCCESS                 0
#define RETERR_IF_TRUE(condition) {if(condition) return FAILURE;}
#define RET_IF_ERR(Func)          {int iRetVal = (Func); \
                                   if (SUCCESS != iRetVal) \
                                     return  iRetVal;}

// Application specific status/error codes
typedef enum{
    // Choosing -0x7D0 to avoid overlap w/ host-driver's error codes
    LAN_CONNECTION_FAILED = -0x7D0,
    INTERNET_CONNECTION_FAILED = LAN_CONNECTION_FAILED - 1,
    DEVICE_NOT_IN_STATION_MODE = INTERNET_CONNECTION_FAILED - 1,

    STATUS_CODE_MAX = -0xBB8
}e_AppStatusCodes;

typedef struct
{
   /* time */
   unsigned long tm_sec;
   unsigned long tm_min;
   unsigned long tm_hour;
   /* date */
   unsigned long tm_day;
   unsigned long tm_mon;
   unsigned long tm_year;
   unsigned long tm_week_day; //not required
   unsigned long tm_year_day; //not required
   unsigned long reserved[3];
}SlDateTime;


//*****************************************************************************
//                 GLOBAL VARIABLES -- Start
//*****************************************************************************
volatile unsigned long  g_ulStatus = 0;//SimpleLink Status
unsigned long  g_ulPingPacketsRecv = 0; //Number of Ping Packets received
unsigned long  g_ulGatewayIP = 0; //Network Gateway IP address
unsigned char  g_ucConnectionSSID[SSID_LEN_MAX+1]; //Connection SSID
unsigned char  g_ucConnectionBSSID[BSSID_LEN_MAX]; //Connection BSSID
signed char    *g_Host = SERVER_NAME;
SlDateTime g_time;
#if defined(ccs) || defined(gcc)
extern void (* const g_pfnVectors[])(void);
#endif
#if defined(ewarm)
extern uVectorEntry __vector_table;
#endif
//*****************************************************************************
//                 GLOBAL VARIABLES -- End
//*****************************************************************************


//****************************************************************************
//                      LOCAL FUNCTION PROTOTYPES
//****************************************************************************
static long WlanConnect();
static int set_time();
static void BoardInit(void);
static long InitializeAppVariables();
static int tls_connect();
static int connectToAccessPoint();
static int http_post(int, char*);
long printErrConvenience(char * msg, long retVal);
void delay(unsigned long ulCount);
//*****************************************************************************
// SimpleLink Asynchronous Event Handlers -- Start
//*****************************************************************************


//*****************************************************************************
//
//! \brief The Function Handles WLAN Events
//!
//! \param[in]  pWlanEvent - Pointer to WLAN Event Info
//!
//! \return None
//!
//*****************************************************************************
int
ProcessReadRegCommand(char* pcInpString1)
{
    unsigned char ucDevAddr, ucRegOffset, ucRdLen;
    unsigned char aucRdDataBuf[256];
    char *pcErrPtr;

    //
    // Get the device address
    //
    char* pcInpString;
    pcInpString = strtok(pcInpString1, " ");
    RETERR_IF_TRUE(pcInpString == NULL);
    ucDevAddr = (unsigned char)strtoul(pcInpString+2, &pcErrPtr, 16);
    //
    // Get the register offset address
    //
    pcInpString = strtok(NULL, " ");
    RETERR_IF_TRUE(pcInpString == NULL);
    ucRegOffset = (unsigned char)strtoul(pcInpString+2, &pcErrPtr, 16);

    //
    // Get the length of data to be read
    //
    pcInpString = strtok(NULL, " ");
    RETERR_IF_TRUE(pcInpString == NULL);
    ucRdLen = (unsigned char)strtoul(pcInpString, &pcErrPtr, 10);
    //RETERR_IF_TRUE(ucLen > sizeof(aucDataBuf));

    //
    // Write the register address to be read from.
    // Stop bit implicitly assumed to be 0.
    //
    RET_IF_ERR(I2C_IF_Write(ucDevAddr,&ucRegOffset,1,0));

    //
    // Read the specified length of data
    //
    RET_IF_ERR(I2C_IF_Read(ucDevAddr, &aucRdDataBuf[0], ucRdLen));

    //UART_PRINT("I2C Read From address complete\n\r");

    //
    // Display the buffer over UART on successful readreg
    //
    //DisplayBuffer(aucRdDataBuf, ucRdLen);

    int retVal = (signed char)aucRdDataBuf[0];
    return retVal;
}

void SimpleLinkWlanEventHandler(SlWlanEvent_t *pWlanEvent) {
    if(!pWlanEvent) {
        return;
    }

    switch(pWlanEvent->Event) {
        case SL_WLAN_CONNECT_EVENT: {
            SET_STATUS_BIT(g_ulStatus, STATUS_BIT_CONNECTION);

            //
            // Information about the connected AP (like name, MAC etc) will be
            // available in 'slWlanConnectAsyncResponse_t'.
            // Applications can use it if required
            //
            //  slWlanConnectAsyncResponse_t *pEventData = NULL;
            // pEventData = &pWlanEvent->EventData.STAandP2PModeWlanConnected;
            //

            // Copy new connection SSID and BSSID to global parameters
            memcpy(g_ucConnectionSSID,pWlanEvent->EventData.
                   STAandP2PModeWlanConnected.ssid_name,
                   pWlanEvent->EventData.STAandP2PModeWlanConnected.ssid_len);
            memcpy(g_ucConnectionBSSID,
                   pWlanEvent->EventData.STAandP2PModeWlanConnected.bssid,
                   SL_BSSID_LENGTH);

            UART_PRINT("[WLAN EVENT] STA Connected to the AP: %s , "
                       "BSSID: %x:%x:%x:%x:%x:%x\n\r",
                       g_ucConnectionSSID,g_ucConnectionBSSID[0],
                       g_ucConnectionBSSID[1],g_ucConnectionBSSID[2],
                       g_ucConnectionBSSID[3],g_ucConnectionBSSID[4],
                       g_ucConnectionBSSID[5]);
        }
        break;

        case SL_WLAN_DISCONNECT_EVENT: {
            slWlanConnectAsyncResponse_t*  pEventData = NULL;

            CLR_STATUS_BIT(g_ulStatus, STATUS_BIT_CONNECTION);
            CLR_STATUS_BIT(g_ulStatus, STATUS_BIT_IP_AQUIRED);

            pEventData = &pWlanEvent->EventData.STAandP2PModeDisconnected;

            // If the user has initiated 'Disconnect' request,
            //'reason_code' is SL_USER_INITIATED_DISCONNECTION
            if(SL_USER_INITIATED_DISCONNECTION == pEventData->reason_code) {
                UART_PRINT("[WLAN EVENT]Device disconnected from the AP: %s,"
                    "BSSID: %x:%x:%x:%x:%x:%x on application's request \n\r",
                           g_ucConnectionSSID,g_ucConnectionBSSID[0],
                           g_ucConnectionBSSID[1],g_ucConnectionBSSID[2],
                           g_ucConnectionBSSID[3],g_ucConnectionBSSID[4],
                           g_ucConnectionBSSID[5]);
            }
            else {
                UART_PRINT("[WLAN ERROR]Device disconnected from the AP AP: %s, "
                           "BSSID: %x:%x:%x:%x:%x:%x on an ERROR..!! \n\r",
                           g_ucConnectionSSID,g_ucConnectionBSSID[0],
                           g_ucConnectionBSSID[1],g_ucConnectionBSSID[2],
                           g_ucConnectionBSSID[3],g_ucConnectionBSSID[4],
                           g_ucConnectionBSSID[5]);
            }
            memset(g_ucConnectionSSID,0,sizeof(g_ucConnectionSSID));
            memset(g_ucConnectionBSSID,0,sizeof(g_ucConnectionBSSID));
        }
        break;

        default: {
            UART_PRINT("[WLAN EVENT] Unexpected event [0x%x]\n\r",
                       pWlanEvent->Event);
        }
        break;
    }
}

//*****************************************************************************
//
//! \brief This function handles network events such as IP acquisition, IP
//!           leased, IP released etc.
//!
//! \param[in]  pNetAppEvent - Pointer to NetApp Event Info
//!
//! \return None
//!
//*****************************************************************************
void SimpleLinkNetAppEventHandler(SlNetAppEvent_t *pNetAppEvent) {
    if(!pNetAppEvent) {
        return;
    }

    switch(pNetAppEvent->Event) {
        case SL_NETAPP_IPV4_IPACQUIRED_EVENT: {
            SlIpV4AcquiredAsync_t *pEventData = NULL;

            SET_STATUS_BIT(g_ulStatus, STATUS_BIT_IP_AQUIRED);

            //Ip Acquired Event Data
            pEventData = &pNetAppEvent->EventData.ipAcquiredV4;

            //Gateway IP address
            g_ulGatewayIP = pEventData->gateway;

            UART_PRINT("[NETAPP EVENT] IP Acquired: IP=%d.%d.%d.%d , "
                       "Gateway=%d.%d.%d.%d\n\r",
            SL_IPV4_BYTE(pNetAppEvent->EventData.ipAcquiredV4.ip,3),
            SL_IPV4_BYTE(pNetAppEvent->EventData.ipAcquiredV4.ip,2),
            SL_IPV4_BYTE(pNetAppEvent->EventData.ipAcquiredV4.ip,1),
            SL_IPV4_BYTE(pNetAppEvent->EventData.ipAcquiredV4.ip,0),
            SL_IPV4_BYTE(pNetAppEvent->EventData.ipAcquiredV4.gateway,3),
            SL_IPV4_BYTE(pNetAppEvent->EventData.ipAcquiredV4.gateway,2),
            SL_IPV4_BYTE(pNetAppEvent->EventData.ipAcquiredV4.gateway,1),
            SL_IPV4_BYTE(pNetAppEvent->EventData.ipAcquiredV4.gateway,0));
        }
        break;

        default: {
            UART_PRINT("[NETAPP EVENT] Unexpected event [0x%x] \n\r",
                       pNetAppEvent->Event);
        }
        break;
    }
}


//*****************************************************************************
//
//! \brief This function handles HTTP server events
//!
//! \param[in]  pServerEvent - Contains the relevant event information
//! \param[in]    pServerResponse - Should be filled by the user with the
//!                                      relevant response information
//!
//! \return None
//!
//****************************************************************************
void SimpleLinkHttpServerCallback(SlHttpServerEvent_t *pHttpEvent, SlHttpServerResponse_t *pHttpResponse) {
    // Unused in this application
}

//*****************************************************************************
//
//! \brief This function handles General Events
//!
//! \param[in]     pDevEvent - Pointer to General Event Info
//!
//! \return None
//!
//*****************************************************************************
void SimpleLinkGeneralEventHandler(SlDeviceEvent_t *pDevEvent) {
    if(!pDevEvent) {
        return;
    }

    //
    // Most of the general errors are not FATAL are are to be handled
    // appropriately by the application
    //
    UART_PRINT("[GENERAL EVENT] - ID=[%d] Sender=[%d]\n\n",
               pDevEvent->EventData.deviceEvent.status,
               pDevEvent->EventData.deviceEvent.sender);
}


//*****************************************************************************
//
//! This function handles socket events indication
//!
//! \param[in]      pSock - Pointer to Socket Event Info
//!
//! \return None
//!
//*****************************************************************************
void SimpleLinkSockEventHandler(SlSockEvent_t *pSock) {
    if(!pSock) {
        return;
    }

    switch( pSock->Event ) {
        case SL_SOCKET_TX_FAILED_EVENT:
            switch( pSock->socketAsyncEvent.SockTxFailData.status) {
                case SL_ECLOSE: 
                    UART_PRINT("[SOCK ERROR] - close socket (%d) operation "
                                "failed to transmit all queued packets\n\n", 
                                    pSock->socketAsyncEvent.SockTxFailData.sd);
                    break;
                default: 
                    UART_PRINT("[SOCK ERROR] - TX FAILED  :  socket %d , reason "
                                "(%d) \n\n",
                                pSock->socketAsyncEvent.SockTxFailData.sd, pSock->socketAsyncEvent.SockTxFailData.status);
                  break;
            }
            break;

        default:
            UART_PRINT("[SOCK EVENT] - Unexpected Event [%x0x]\n\n",pSock->Event);
          break;
    }
}


//*****************************************************************************
// SimpleLink Asynchronous Event Handlers -- End
//*****************************************************************************


//*****************************************************************************
//
//! \brief This function initializes the application variables
//!
//! \param    0 on success else error code
//!
//! \return None
//!
//*****************************************************************************
static long InitializeAppVariables() {
    g_ulStatus = 0;
    g_ulGatewayIP = 0;
    g_Host = SERVER_NAME;
    memset(g_ucConnectionSSID,0,sizeof(g_ucConnectionSSID));
    memset(g_ucConnectionBSSID,0,sizeof(g_ucConnectionBSSID));
    return SUCCESS;
}


//*****************************************************************************
//! \brief This function puts the device in its default state. It:
//!           - Set the mode to STATION
//!           - Configures connection policy to Auto and AutoSmartConfig
//!           - Deletes all the stored profiles
//!           - Enables DHCP
//!           - Disables Scan policy
//!           - Sets Tx power to maximum
//!           - Sets power policy to normal
//!           - Unregister mDNS services
//!           - Remove all filters
//!
//! \param   none
//! \return  On success, zero is returned. On error, negative is returned
//*****************************************************************************
static long ConfigureSimpleLinkToDefaultState() {
    SlVersionFull   ver = {0};
    _WlanRxFilterOperationCommandBuff_t  RxFilterIdMask = {0};

    unsigned char ucVal = 1;
    unsigned char ucConfigOpt = 0;
    unsigned char ucConfigLen = 0;
    unsigned char ucPower = 0;

    long lRetVal = -1;
    long lMode = -1;

    lMode = sl_Start(0, 0, 0);
    ASSERT_ON_ERROR(lMode);

    // If the device is not in station-mode, try configuring it in station-mode 
    if (ROLE_STA != lMode) {
        if (ROLE_AP == lMode) {
            // If the device is in AP mode, we need to wait for this event 
            // before doing anything 
            while(!IS_IP_ACQUIRED(g_ulStatus)) {
#ifndef SL_PLATFORM_MULTI_THREADED
              _SlNonOsMainLoopTask(); 
#endif
            }
        }

        // Switch to STA role and restart 
        lRetVal = sl_WlanSetMode(ROLE_STA);
        ASSERT_ON_ERROR(lRetVal);

        lRetVal = sl_Stop(0xFF);
        ASSERT_ON_ERROR(lRetVal);

        lRetVal = sl_Start(0, 0, 0);
        ASSERT_ON_ERROR(lRetVal);

        // Check if the device is in station again 
        if (ROLE_STA != lRetVal) {
            // We don't want to proceed if the device is not coming up in STA-mode 
            return DEVICE_NOT_IN_STATION_MODE;
        }
    }
    
    // Get the device's version-information
    ucConfigOpt = SL_DEVICE_GENERAL_VERSION;
    ucConfigLen = sizeof(ver);
    lRetVal = sl_DevGet(SL_DEVICE_GENERAL_CONFIGURATION, &ucConfigOpt, 
                                &ucConfigLen, (unsigned char *)(&ver));
    ASSERT_ON_ERROR(lRetVal);
    
    UART_PRINT("Host Driver Version: %s\n\r",SL_DRIVER_VERSION);
    UART_PRINT("Build Version %d.%d.%d.%d.31.%d.%d.%d.%d.%d.%d.%d.%d\n\r",
    ver.NwpVersion[0],ver.NwpVersion[1],ver.NwpVersion[2],ver.NwpVersion[3],
    ver.ChipFwAndPhyVersion.FwVersion[0],ver.ChipFwAndPhyVersion.FwVersion[1],
    ver.ChipFwAndPhyVersion.FwVersion[2],ver.ChipFwAndPhyVersion.FwVersion[3],
    ver.ChipFwAndPhyVersion.PhyVersion[0],ver.ChipFwAndPhyVersion.PhyVersion[1],
    ver.ChipFwAndPhyVersion.PhyVersion[2],ver.ChipFwAndPhyVersion.PhyVersion[3]);

    // Set connection policy to Auto + SmartConfig 
    //      (Device's default connection policy)
    lRetVal = sl_WlanPolicySet(SL_POLICY_CONNECTION, 
                                SL_CONNECTION_POLICY(1, 0, 0, 0, 1), NULL, 0);
    ASSERT_ON_ERROR(lRetVal);

    // Remove all profiles
    lRetVal = sl_WlanProfileDel(0xFF);
    ASSERT_ON_ERROR(lRetVal);

    

    //
    // Device in station-mode. Disconnect previous connection if any
    // The function returns 0 if 'Disconnected done', negative number if already
    // disconnected Wait for 'disconnection' event if 0 is returned, Ignore 
    // other return-codes
    //
    lRetVal = sl_WlanDisconnect();
    if(0 == lRetVal) {
        // Wait
        while(IS_CONNECTED(g_ulStatus)) {
#ifndef SL_PLATFORM_MULTI_THREADED
              _SlNonOsMainLoopTask(); 
#endif
        }
    }

    // Enable DHCP client
    lRetVal = sl_NetCfgSet(SL_IPV4_STA_P2P_CL_DHCP_ENABLE,1,1,&ucVal);
    ASSERT_ON_ERROR(lRetVal);

    // Disable scan
    ucConfigOpt = SL_SCAN_POLICY(0);
    lRetVal = sl_WlanPolicySet(SL_POLICY_SCAN , ucConfigOpt, NULL, 0);
    ASSERT_ON_ERROR(lRetVal);

    // Set Tx power level for station mode
    // Number between 0-15, as dB offset from max power - 0 will set max power
    ucPower = 0;
    lRetVal = sl_WlanSet(SL_WLAN_CFG_GENERAL_PARAM_ID, 
            WLAN_GENERAL_PARAM_OPT_STA_TX_POWER, 1, (unsigned char *)&ucPower);
    ASSERT_ON_ERROR(lRetVal);

    // Set PM policy to normal
    lRetVal = sl_WlanPolicySet(SL_POLICY_PM , SL_NORMAL_POLICY, NULL, 0);
    ASSERT_ON_ERROR(lRetVal);

    // Unregister mDNS services
    lRetVal = sl_NetAppMDNSUnRegisterService(0, 0);
    ASSERT_ON_ERROR(lRetVal);

    // Remove  all 64 filters (8*8)
    memset(RxFilterIdMask.FilterIdMask, 0xFF, 8);
    lRetVal = sl_WlanRxFilterSet(SL_REMOVE_RX_FILTER, (_u8 *)&RxFilterIdMask,
                       sizeof(_WlanRxFilterOperationCommandBuff_t));
    ASSERT_ON_ERROR(lRetVal);

    lRetVal = sl_Stop(SL_STOP_TIMEOUT);
    ASSERT_ON_ERROR(lRetVal);

    InitializeAppVariables();
    
    return lRetVal; // Success
}


//*****************************************************************************
//
//! Board Initialization & Configuration
//!
//! \param  None
//!
//! \return None
//
//*****************************************************************************
static void BoardInit(void) {
/* In case of TI-RTOS vector table is initialize by OS itself */
#ifndef USE_TIRTOS
  //
  // Set vector table base
  //
#if defined(ccs)
    MAP_IntVTableBaseSet((unsigned long)&g_pfnVectors[0]);
#endif
#if defined(ewarm)
    MAP_IntVTableBaseSet((unsigned long)&__vector_table);
#endif
#endif
    //
    // Enable Processor
    //
    MAP_IntMasterEnable();
    MAP_IntEnable(FAULT_SYSTICK);

    PRCMCC3200MCUInit();
}


//****************************************************************************
//
//! \brief Connecting to a WLAN Accesspoint
//!
//!  This function connects to the required AP (SSID_NAME) with Security
//!  parameters specified in te form of macros at the top of this file
//!
//! \param  None
//!
//! \return  0 on success else error code
//!
//! \warning    If the WLAN connection fails or we don't aquire an IP
//!            address, It will be stuck in this function forever.
//
//****************************************************************************
static long WlanConnect() {
    SlSecParams_t secParams = {0};
    long lRetVal = 0;

    secParams.Key = SECURITY_KEY;
    secParams.KeyLen = strlen(SECURITY_KEY);
    secParams.Type = SECURITY_TYPE;

    UART_PRINT("Attempting connection to access point: ");
    UART_PRINT(SSID_NAME);
    UART_PRINT("... ...");
    lRetVal = sl_WlanConnect(SSID_NAME, strlen(SSID_NAME), 0, &secParams, 0);
    ASSERT_ON_ERROR(lRetVal);

    UART_PRINT(" Connected!!!\n\r");


    // Wait for WLAN Event
    while((!IS_CONNECTED(g_ulStatus)) || (!IS_IP_ACQUIRED(g_ulStatus))) {
        // Toggle LEDs to Indicate Connection Progress
        _SlNonOsMainLoopTask();
        GPIO_IF_LedOff(MCU_IP_ALLOC_IND);
        MAP_UtilsDelay(800000);
        _SlNonOsMainLoopTask();
        GPIO_IF_LedOn(MCU_IP_ALLOC_IND);
        MAP_UtilsDelay(800000);
    }

    return SUCCESS;

}

//*****************************************************************************
//
//! This function updates the date and time of CC3200.
//!
//! \param None
//!
//! \return
//!     0 for success, negative otherwise
//!
//*****************************************************************************

static int set_time() {
    long retVal;

    g_time.tm_day = DATE;
    g_time.tm_mon = MONTH;
    g_time.tm_year = YEAR;
    g_time.tm_sec = HOUR;
    g_time.tm_hour = MINUTE;
    g_time.tm_min = SECOND;

    retVal = sl_DevSet(SL_DEVICE_GENERAL_CONFIGURATION,
                          SL_DEVICE_GENERAL_CONFIGURATION_DATE_TIME,
                          sizeof(SlDateTime),(unsigned char *)(&g_time));

    ASSERT_ON_ERROR(retVal);
    return SUCCESS;
}

//*****************************************************************************
//
//! This function demonstrates how certificate can be used with SSL.
//! The procedure includes the following steps:
//! 1) connect to an open AP
//! 2) get the server name via a DNS request
//! 3) define all socket options and point to the CA certificate
//! 4) connect to the server via TCP
//!
//! \param None
//!
//! \return  0 on success else error code
//! \return  LED1 is turned solid in case of success
//!    LED2 is turned solid in case of failure
//!
//*****************************************************************************
static int tls_connect() {
    SlSockAddrIn_t    Addr;
    int    iAddrSize;
    unsigned char    ucMethod = SL_SO_SEC_METHOD_TLSV1_2;
    unsigned int uiIP,uiCipher = SL_SEC_MASK_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA;
    long lRetVal = -1;
    int iSockID;

    lRetVal = sl_NetAppDnsGetHostByName(g_Host, strlen((const char *)g_Host),
                                    (unsigned long*)&uiIP, SL_AF_INET);

    if(lRetVal < 0) {
        return printErrConvenience("Device couldn't retrieve the host name \n\r", lRetVal);
    }

    Addr.sin_family = SL_AF_INET;
    Addr.sin_port = sl_Htons(GOOGLE_DST_PORT);
    Addr.sin_addr.s_addr = sl_Htonl(uiIP);
    iAddrSize = sizeof(SlSockAddrIn_t);
    //
    // opens a secure socket 
    //
    iSockID = sl_Socket(SL_AF_INET,SL_SOCK_STREAM, SL_SEC_SOCKET);
    if( iSockID < 0 ) {
        return printErrConvenience("Device unable to create secure socket \n\r", lRetVal);
    }

    //
    // configure the socket as TLS1.2
    //
    lRetVal = sl_SetSockOpt(iSockID, SL_SOL_SOCKET, SL_SO_SECMETHOD, &ucMethod,\
                               sizeof(ucMethod));
    if(lRetVal < 0) {
        return printErrConvenience("Device couldn't set socket options \n\r", lRetVal);
    }
    //
    //configure the socket as ECDHE RSA WITH AES256 CBC SHA
    //
    lRetVal = sl_SetSockOpt(iSockID, SL_SOL_SOCKET, SL_SO_SECURE_MASK, &uiCipher,\
                           sizeof(uiCipher));
    if(lRetVal < 0) {
        return printErrConvenience("Device couldn't set socket options \n\r", lRetVal);
    }

    //
    //configure the socket with CA certificate - for server verification
    //
    lRetVal = sl_SetSockOpt(iSockID, SL_SOL_SOCKET, \
                           SL_SO_SECURE_FILES_CA_FILE_NAME, \
                           SL_SSL_CA_CERT, \
                           strlen(SL_SSL_CA_CERT));

    if(lRetVal < 0) {
        return printErrConvenience("Device couldn't set socket options \n\r", lRetVal);
    }

    //configure the socket with Client Certificate - for server verification
    //
    lRetVal = sl_SetSockOpt(iSockID, SL_SOL_SOCKET, \
                SL_SO_SECURE_FILES_CERTIFICATE_FILE_NAME, \
                                    SL_SSL_CLIENT, \
                           strlen(SL_SSL_CLIENT));

    if(lRetVal < 0) {
        return printErrConvenience("Device couldn't set socket options \n\r", lRetVal);
    }

    //configure the socket with Private Key - for server verification
    //
    lRetVal = sl_SetSockOpt(iSockID, SL_SOL_SOCKET, \
            SL_SO_SECURE_FILES_PRIVATE_KEY_FILE_NAME, \
            SL_SSL_PRIVATE, \
                           strlen(SL_SSL_PRIVATE));

    if(lRetVal < 0) {
        return printErrConvenience("Device couldn't set socket options \n\r", lRetVal);
    }


    /* connect to the peer device - Google server */
    lRetVal = sl_Connect(iSockID, ( SlSockAddr_t *)&Addr, iAddrSize);

    if(lRetVal < 0) {
        UART_PRINT("Device couldn't connect to server:");
        UART_PRINT(SERVER_NAME);
        UART_PRINT("\n\r");
        return printErrConvenience("Device couldn't connect to server \n\r", lRetVal);
    }
    else {
        UART_PRINT("Device has connected to the website:");
        UART_PRINT(SERVER_NAME);
        UART_PRINT("\n\r");
    }

    GPIO_IF_LedOff(MCU_RED_LED_GPIO);
    GPIO_IF_LedOn(MCU_GREEN_LED_GPIO);
    return iSockID;
}



long printErrConvenience(char * msg, long retVal) {
    UART_PRINT(msg);
    GPIO_IF_LedOn(MCU_RED_LED_GPIO);
    return retVal;
}



int connectToAccessPoint() {
    long lRetVal = -1;
    GPIO_IF_LedConfigure(LED1|LED3);

    GPIO_IF_LedOff(MCU_RED_LED_GPIO);
    GPIO_IF_LedOff(MCU_GREEN_LED_GPIO);

    lRetVal = InitializeAppVariables();
    ASSERT_ON_ERROR(lRetVal);

    //
    // Following function configure the device to default state by cleaning
    // the persistent settings stored in NVMEM (viz. connection profiles &
    // policies, power policy etc)
    //
    // Applications may choose to skip this step if the developer is sure
    // that the device is in its default state at start of applicaton
    //
    // Note that all profiles and persistent settings that were done on the
    // device will be lost
    //
    lRetVal = ConfigureSimpleLinkToDefaultState();
    if(lRetVal < 0) {
      if (DEVICE_NOT_IN_STATION_MODE == lRetVal)
          UART_PRINT("Failed to configure the device in its default state \n\r");

      return lRetVal;
    }

    UART_PRINT("Device is configured in default state \n\r");

    CLR_STATUS_BIT_ALL(g_ulStatus);

    ///
    // Assumption is that the device is configured in station mode already
    // and it is in its default state
    //
    lRetVal = sl_Start(0, 0, 0);
    if (lRetVal < 0 || ROLE_STA != lRetVal) {
        UART_PRINT("Failed to start the device \n\r");
        return lRetVal;
    }

    UART_PRINT("Device started as STATION \n\r");

    //
    //Connecting to WLAN AP
    //
    lRetVal = WlanConnect();
    if(lRetVal < 0) {
        UART_PRINT("Failed to establish connection w/ an AP \n\r");
        GPIO_IF_LedOn(MCU_RED_LED_GPIO);
        return lRetVal;
    }

    UART_PRINT("Connection established w/ AP and IP is aquired \n\r");
    return 0;
}

//*****************************************************************************
//
//! Main 
//!
//! \param  none
//!
//! \return None
//!
//*****************************************************************************


struct ball {
    int xPos;
    int yPos;

    int xStep;
    int yStep;

    int inGame;
};

void main() {

    long lRetVal = -1;
    //
    // Initialize board configuration
    //
    BoardInit();

    PinMuxConfig();

    InitTerm();
    ClearTerm();

    //Connect the CC3200 to the local access point
    lRetVal = connectToAccessPoint();
    //Set time so that encryption can be used
    lRetVal = set_time();
    if(lRetVal < 0) {
        UART_PRINT("Unable to set time in the device");
        LOOP_FOREVER();
    }
    //Connect to the website with TLS encryption
    lRetVal = tls_connect();
    if(lRetVal < 0) {
        ERR_PRINT(lRetVal);
    }

    I2C_IF_Open(I2C_MASTER_MODE_FST);

        MAP_PRCMPeripheralReset(PRCM_GSPI);
            MAP_PRCMPeripheralClkEnable(PRCM_GSPI,PRCM_RUN_MODE_CLK);
            MAP_SPIReset(GSPI_BASE);
            MAP_SPIConfigSetExpClk(GSPI_BASE,MAP_PRCMPeripheralClockGet(PRCM_GSPI),
                             SPI_IF_BIT_RATE,SPI_MODE_MASTER,SPI_SUB_MODE_0,
                             (SPI_SW_CTRL_CS |
                             SPI_4PIN_MODE |
                             SPI_TURBO_OFF |
                             SPI_CS_ACTIVELOW |
                             SPI_WL_8));
            MAP_SPIEnable(GSPI_BASE);
            MAP_SPIFIFOEnable(GSPI_BASE,SPI_TX_FIFO);
            Adafruit_Init();
            fillScreen(BLACK);

            char* printer = DATA2;
            int x = 64;
                int xReg = 0;

                int y = 95;
                int yReg = 1;

                struct ball balls[10];
                int ballSize = 10;
                drawRect(0,8,4,52,WHITE);//Top Left
                drawRect(0,68,4,52,WHITE);//Bottom Left
                drawRect(1,69,2,50,WHITE);
                drawRect(124,8,4,52,WHITE);//Top Right
                drawRect(125,9,2,50,WHITE);
                drawRect(124,68,4,52,WHITE);//Bottom Right
                drawRect(125,69,2,50,WHITE);

                drawRect(9,0,111,2,WHITE);// Top Horizontal
                drawRect(9,126,111,2,WHITE);//Bottom Horizontal

                OutstrXYC("<Power Meter(SW3)", 6, 34, WHITE, WHITE);
                OutstrXYC("^Pocket 1,", 6, 8, WHITE, WHITE);
                OutstrXYC("Pocket 2^", 66, 8, WHITE, WHITE);
                OutstrXYC("<Pocket 3,", 6, 60, WHITE, WHITE);
                OutstrXYC("Pocket 4>", 66, 60, WHITE, WHITE);
                OutstrXYC("vPocket 5,", 6, 110, WHITE, WHITE);
                OutstrXYC("Pocket 6v", 66, 110, WHITE, WHITE);
                for(;y < 97; y++) {
                    while (yReg < 50) {
                        drawRect(1,59-yReg,2,yReg+1,WHITE);
                        yReg++;
                        delay(2);
                    }
                    while(yReg > 0) {
                        drawRect(1,9,2,51 - yReg,BLACK);
                        yReg--;
                        delay(2);
                    }
                }
                delay(100);
                OutstrXYC("<Power Meter(SW3)", 6, 34, BLACK, BLACK);
                OutstrXYC("^Pocket 1,", 6, 8, BLACK, BLACK);
                OutstrXYC("Pocket 2^", 66, 8, BLACK, BLACK);
                OutstrXYC("<Pocket 3,", 6, 60, BLACK, BLACK);
                OutstrXYC("Pocket 4>", 66, 60, BLACK, BLACK);
                OutstrXYC("vPocket 5,", 6, 110, BLACK, BLACK);
                OutstrXYC("Pocket 6v", 66, 110, BLACK, BLACK);


                balls[0].xPos = 64;
                balls[0].yPos = 44;
                balls[0].inGame = 1;
                drawCircle(64,44,2,WHITE);//1, First Row

                balls[1].xPos = 61;
                balls[1].yPos = 39;
                balls[1].inGame = 1;
                drawCircle(61,39,2,WHITE);//2, Second Row, Left
                balls[2].xPos = 67;
                balls[2].yPos = 39;
                balls[2].inGame = 1;
                drawCircle(67,39,2,WHITE);//3, Second Row, Right

                balls[3].xPos = 59;
                balls[3].yPos = 34;
                balls[3].inGame = 1;
                drawCircle(59,34,2,WHITE);//4, Third Row, Left
                balls[4].xPos = 64;
                balls[4].yPos = 34;
                balls[4].inGame = 1;
                drawCircle(64,34,2,WHITE);//5, Third Row, Middle
                balls[5].xPos = 69;
                balls[5].yPos = 34;
                balls[5].inGame = 1;
                drawCircle(69,34,2,WHITE);//6, Third Row, Right

                balls[6].xPos = 55;
                balls[6].yPos = 29;
                balls[6].inGame = 1;
                drawCircle(55,29,2,WHITE);//7, Fourth Row, Far Left
                balls[7].xPos = 61;
                balls[7].yPos = 29;
                balls[7].inGame = 1;
                drawCircle(61,29,2,WHITE);//8, Fourth Row, Middle Left
                balls[8].xPos = 67;
                balls[8].yPos = 29;
                balls[8].inGame = 1;
                drawCircle(67,29,2,WHITE);//9, Fourth Row, Middle Right
                balls[9].xPos = 73;
                balls[9].yPos = 29;
                balls[9].inGame = 1;
                drawCircle(73,29,2,WHITE);//10, Fourth Row, Far Right

                drawCircle(x,y,2,WHITE);//Cue ball
                fillCircle(x,y,2,WHITE);

                while (ballSize > 0) {
                    long sw3 = 0;
                    int power = 0;

                    drawRect(1,9,1,50,BLACK);
                    while(1) {
                        while (power < 50) {
                            drawRect(1,59-power,2,power+1,WHITE);
                            power++;
                            delay(2);
                            sw3 = GPIOPinRead(GPIOA1_BASE, 0x20);
                            if(sw3) {break;}
                        }
                        sw3 = GPIOPinRead(GPIOA1_BASE, 0x20);
                        if(sw3) {break;}
                        while(power > 0) {
                            drawRect(1,9,2,51 - power,BLACK);
                            power--;
                            delay(2);
                            sw3 = GPIOPinRead(GPIOA1_BASE, 0x20);
                            if(sw3) {break;}
                        }
                        if(sw3) {break;}
                    }

                    long sw2 = 0;
                    int xCur = x;
                    int yCur = y+4;
                    drawPixel(xCur,yCur,WHITE);
                    while(1) {
                        char xCom[11] = "0x18 0x3 1";
                        char yCom[11] = "0x18 0x5 1";
                        yReg = ProcessReadRegCommand(yCom);
                        xReg = ProcessReadRegCommand(xCom);


                        drawPixel(xCur,yCur,BLACK);

                        if(yCur == y+4 || yCur == y-4) {
                            if(yReg > 5 || yReg < -5) {
                                xCur += 2 * (yReg > 0 ? 1 : -1);
                            }
                        }
                        if(xCur > x+4) {xCur = x+4;}
                        if(xCur < x-4) {xCur = x-4;}

                        if(xCur == x+4 || xCur == x-4) {
                            if(xReg > 5 || xReg < -5) {
                                yCur += 2 * (xReg > 0 ? 1 : -1);
                            }
                        }
                        if(yCur > y+4) {yCur = y+4;}
                        if(yCur < y-4) {yCur = y-4;}

                        xCom[0] = '\0';
                        yCom[0] = '\0';

                        drawPixel(xCur,yCur,WHITE);
                        delay(10);

                        sw2 = GPIOPinRead(GPIOA2_BASE, 0x40);
                        if(sw2) {
                            drawPixel(xCur,yCur,BLACK);
                            break;
                        }
                    }

                    double slope = x == xCur ? 100 : (double)(y - yCur)/(double)(x - xCur);

                    int xStep;
                    int goRight = (xCur < x);
                    int yStep;
                    int goUp = (yCur > y);

                    if(slope == 0) {
                        xStep = (power > 9 ? (power/5) : 2) * (goRight ? 1 : -1);
                        yStep = 0;
                    } else if(slope == 100) {
                        xStep = 0;
                        yStep = (power > 9 ? (power/5) : 2) * (goUp ? -1 : 1);
                    } else if(slope == 0.5 || slope == -0.5){
                        xStep = (2 + (power/10)) * (goRight ? 1 : -1);
                        yStep = (2 + (power/15)) * (goUp ? -1 : 1);
                    } else if(slope == 1 || slope == -1) {

                        xStep = (3 + (power/15)) * (goRight ? 1 : -1);
                        yStep = (3 + (power/15)) * (goUp ? -1 : 1);
                    } else if(slope == 2 || slope == -2) {

                        xStep = (2 + (power/15)) * (goRight ? 1 : -1);
                        yStep = (2 + (power/10)) * (goUp ? -1 : 1);
                    }

                    int numSteps = 0;
                    for(; numSteps < 10; numSteps++) {
                        drawCircle(x,y,2,BLACK);
                        fillCircle(x,y,2,BLACK);


                        x += xStep;
                        y += yStep;
                        if(x < 8) {
                            x = 8;
                            xStep *= -1;
                        }
                        if(y < 5) {
                            y = 5;
                            yStep *= -1;
                        }
                        if(x > 120) {
                            x = 120;
                            xStep *= -1;
                        }
                        if(y > 123) {
                            y = 123;
                            yStep *= -1;
                        }


                        drawCircle(x,y,2,WHITE);
                        fillCircle(x,y,2,WHITE);


                        int j = 0;
                        for(; j < 10; j++) {
                            if(balls[j].inGame) {
                                if((balls[j].xPos >= x-4 && balls[j].xPos <= x+4)
                                   && (balls[j].yPos) >= y-4 && balls[j].yPos <= y+4) {
                                    if(balls[j].xStep == 0 && balls[j].yStep == 0) {
                                        int slopeQ2B =
                                                x == balls[j].xPos ?
                                                100 :
                                                (double)(balls[j].yPos - y)/(double)(balls[j].xPos - x);
                                        if(slopeQ2B == 0 || slopeQ2B == 100) {
                                            balls[j].xStep = xStep;
                                            balls[j].yStep = yStep;
                                        } else {
                                            int goRightB = (x < balls[j].xPos);
                                            int goUpB = (y > balls[j].yPos);
                                            if((slopeQ2B > 0.25 && slopeQ2B < 0.75) || (slopeQ2B < -0.25 && slopeQ2B >- 0.75)){
                                                balls[j].xStep = (2 + (power/10)) * (goRightB ? 1 : -1);
                                                balls[j].yStep = (2 + (power/15)) * (goUpB ? -1 : 1);
                                            } else if((slopeQ2B >= 0.75 && slopeQ2B <= 1.5) || (slopeQ2B <= -0.75 && slopeQ2B >= -1.5)) {
                                                balls[j].xStep = (3 + (power/15)) * (goRightB ? 1 : -1);
                                                balls[j].yStep = (3 + (power/15)) * (goUpB ? -1 : 1);
                                            } else if(slopeQ2B > 1.5 || slopeQ2B < -1.5) {
                                                balls[j].xStep = (2 + (power/15)) * (goRightB ? 1 : -1);
                                                balls[j].yStep = (2 + (power/10)) * (goUpB ? -1 : 1);
                                            }
                                        }
                                    }

                                    int xWasNeg = xStep < 0 ? 1 : 0;
                                    int yWasNeg = yStep < 0 ? 1 : 0;
                                    xStep += xWasNeg ? 1 : -1;
                                    yStep += yWasNeg ? 1 : -1;
                                    if(xStep == 0) xStep = xWasNeg ? -1 : 1;
                                    if(yStep == 0) yStep= yWasNeg ? -1 : 1;

                                }
                            } else continue;

                            drawCircle(balls[j].xPos,balls[j].yPos,2,BLACK);

                            balls[j].xPos += balls[j].xStep;
                            balls[j].yPos += balls[j].yStep;

                            if(balls[j].xPos < 8) {
                                balls[j].xPos = 8;
                                balls[j].xStep *= -1;
                            }
                            if(balls[j].yPos < 5) {
                                balls[j].yPos = 5;
                                balls[j].yStep *= -1;
                            }
                            if(balls[j].xPos > 120) {
                                balls[j].xPos = 120;
                                balls[j].xStep *= -1;
                            }
                            if(balls[j].yPos > 123) {
                                balls[j].yPos = 123;
                                balls[j].yStep *= -1;
                            }

                            drawCircle(balls[j].xPos,balls[j].yPos,2,WHITE);

                            if(balls[j].xPos < 12 || balls[j].xPos > 116) {
                                int pocket = balls[j].xPos < 12 ? -1 : 0;
                                if(balls[j].yPos < 12) pocket += 2;
                                if(balls[j].yPos > 57 && balls[j].yPos < 71) pocket += 4;
                                if(balls[j].yPos > 116) pocket += 6;

                                if(pocket > 0) {
                                    balls[j].inGame = 0;
                                    ballSize--;
                                    drawCircle(balls[j].xPos,balls[j].yPos,2,BLACK);
                                    printer[97] = j+48;
                                    printer[116] = pocket+48;
                                    http_post(lRetVal, printer);
                                }
                            }
                        }
                    }

                    int k = 0;
                    for(; k < 10; k++) {
                        balls[k].xStep = 0;
                        balls[k].yStep = 0;
                    }
                }

    http_post(lRetVal, DATA1);

    sl_Stop(SL_STOP_TIMEOUT);
    LOOP_FOREVER();
}
//*****************************************************************************
//
// Close the Doxygen group.
//! @}
//
//*****************************************************************************

static int http_post(int iTLSSockID, char* printData){
    char acSendBuff[512];
    char acRecvbuff[1460];
    char cCLLength[200];
    char* pcBufHeaders;
    int lRetVal = 0;

    pcBufHeaders = acSendBuff;
    strcpy(pcBufHeaders, POSTHEADER);
    pcBufHeaders += strlen(POSTHEADER);
    strcpy(pcBufHeaders, HOSTHEADER);
    pcBufHeaders += strlen(HOSTHEADER);
    strcpy(pcBufHeaders, CHEADER);
    pcBufHeaders += strlen(CHEADER);
    strcpy(pcBufHeaders, "\r\n\r\n");

    int dataLength = strlen(printData);

    strcpy(pcBufHeaders, CTHEADER);
    pcBufHeaders += strlen(CTHEADER);
    strcpy(pcBufHeaders, CLHEADER1);

    pcBufHeaders += strlen(CLHEADER1);
    sprintf(cCLLength, "%d", dataLength);

    strcpy(pcBufHeaders, cCLLength);
    pcBufHeaders += strlen(cCLLength);
    strcpy(pcBufHeaders, CLHEADER2);
    pcBufHeaders += strlen(CLHEADER2);

    strcpy(pcBufHeaders, printData);
    pcBufHeaders += strlen(printData);

    int testDataLength = strlen(pcBufHeaders);

    UART_PRINT(acSendBuff);


    //
    // Send the packet to the server */
    //
    lRetVal = sl_Send(iTLSSockID, acSendBuff, strlen(acSendBuff), 0);
    if(lRetVal < 0) {
        UART_PRINT("POST failed. Error Number: %i\n\r",lRetVal);
        sl_Close(iTLSSockID);
        GPIO_IF_LedOn(MCU_RED_LED_GPIO);
        return lRetVal;
    }
    lRetVal = sl_Recv(iTLSSockID, &acRecvbuff[0], sizeof(acRecvbuff), 0);
    if(lRetVal < 0) {
        UART_PRINT("Received failed. Error Number: %i\n\r",lRetVal);
        //sl_Close(iSSLSockID);
        GPIO_IF_LedOn(MCU_RED_LED_GPIO);
           return lRetVal;
    }
    else {
        acRecvbuff[lRetVal+1] = '\0';
        UART_PRINT(acRecvbuff);
        UART_PRINT("\n\r\n\r");
    }

    return 0;
}
