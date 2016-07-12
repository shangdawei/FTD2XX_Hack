#include "stdafx.h"
#include <stdio.h>
#include "FTD2XX_Hack.h"

#ifndef _WIN64
#define FTD2XX_LIBNAME (LPCWSTR(L"ftd2xx.dll"))
#else 
#define FTD2XX_LIBNAME (LPCWSTR(L"ftd2xx64.dll"))
#endif 

const char * pszNibbleToHex =
{
  "0123456789ABCDEF"
};

typedef enum
{
  LAST_UNKNOWN = 0, LAST_READ = 1, LAST_WRITE = 2
} LAST_ACTION;

LAST_ACTION lastAction = LAST_UNKNOWN;

#ifdef _DEBUG
#define READ_BUFFER_SIZE ( 32 )
#define WRITE_BUFFER_SIZE ( 32 )
#else 
#define READ_BUFFER_SIZE ( 1024 )
#define WRITE_BUFFER_SIZE ( 1024 )
#endif 
char readBuffer[READ_BUFFER_SIZE];
char writeBuffer[WRITE_BUFFER_SIZE];

DWORD readIndex = 0;
DWORD writeIndex = 0;

void HexDump(char * info, int infoLength, char * buffer)
{
  BYTE nNibble;
  int i;

  if (infoLength > 0)
  {
    if (info != NULL)
    {
      for (i = 0; i < infoLength; i++)
      {
        nNibble = (info[i] >> 4) & 0x0F;
        buffer[3 * i + 0] = pszNibbleToHex[nNibble];
        nNibble = (info[i] >> 0) & 0x0F;
        buffer[3 * i + 1] = pszNibbleToHex[nNibble];

        buffer[3 * i + 2] = 0x20;
      }
    }

    buffer[(infoLength * 3)] = 0;
  }
}

void DumpBuffer(LAST_ACTION action)
{
  char * info;
  char * buffer;
  char OutputString[256];
  DWORD index;
  DWORD lineCount;
  // Dump Buffer from 0 to Index-1
  if (action == LAST_WRITE)
  {
    sprintf_s(OutputString, 256, "FTD2XX > ");
    info = (char*)writeBuffer;
    index = writeIndex;
  }
  else if (action == LAST_READ)
  {
    sprintf_s(OutputString, 256, "FTD2XX < ");
    info = (char*)readBuffer;
    index = readIndex;
  }
  else
  {
    return;
  }

  buffer = (char*)&OutputString[9];

  lineCount = ((index + 15) >> 4);
  for (DWORD i = 0; i < lineCount; i++)
  {
    HexDump(info + (i << 4), (index > 15) ? 16 : index, buffer);

    OutputDebugStringA(OutputString);
    index -= 16;
  }

  if (action == LAST_WRITE)
  {
    writeIndex = 0;
  }
  else
  {
    readIndex = 0;
  }

  if (lineCount)
    OutputDebugStringA(
      "FTD2XX : -----------------------------------------------------------");
}

FTD2XX_API FT_STATUS WINAPI FT_Initialise(void)
{
  typedef FT_STATUS(WINAPI * FT_Initialise_T)(void);

  HMODULE hModule;
  FT_Initialise_T FT_Initialise;

  OutputDebugStringA("FTD2XX : FT_Open");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_Initialise = (FT_Initialise_T)GetProcAddress(hModule, "FT_Initialise"
    );
    if (FT_Open != 0)
      return FT_Initialise();
  }

  return FT_INVALID_HANDLE;
}

FTD2XX_API void WINAPI FT_Finalise(void)
{
  typedef FT_STATUS(WINAPI * FT_Finalise_T)(void);

  HMODULE hModule;
  FT_Finalise_T FT_Finalise;

  OutputDebugStringA("FTD2XX : FT_Open");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_Finalise = (FT_Finalise_T)GetProcAddress(hModule, "FT_Finalise");
    if (FT_Open != 0)
      FT_Finalise();
  }
}

FT_STATUS WINAPI FT_Open(int deviceNumber, FT_HANDLE * pHandle)
{
  typedef FT_STATUS(WINAPI * FT_Open_T)(int deviceNumber, FT_HANDLE *
    pHandle);

  HMODULE hModule;
  FT_Open_T FT_Open;

  OutputDebugStringA(
    "====================FTD2XX : FT_Open================================");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_Open = (FT_Open_T)GetProcAddress(hModule, "FT_Open");
    if (FT_Open != 0)
      return FT_Open(deviceNumber, pHandle);
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_OpenEx(PVOID pArg1, DWORD Flags, FT_HANDLE * pHandle)
{
  typedef FT_STATUS(WINAPI * FT_OpenEx_T)(PVOID pArg1, DWORD Flags,
    FT_HANDLE * pHandle);

  HMODULE hModule;
  FT_OpenEx_T FT_OpenEx;

  OutputDebugStringA("FTD2XX : FT_OpenEx");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_OpenEx = (FT_OpenEx_T)GetProcAddress(hModule, "FT_OpenEx");
    if (FT_OpenEx != 0)
      return FT_OpenEx(pArg1, Flags, pHandle);
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_ListDevices(PVOID pArg1, PVOID pArg2, DWORD Flags)
{
  typedef FT_STATUS(WINAPI * FT_ListDevices_T)(PVOID pArg1, PVOID pArg2,
    DWORD Flags);

  HMODULE hModule;
  FT_ListDevices_T FT_ListDevices;

  OutputDebugStringA("FTD2XX : FT_ListDevices");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_ListDevices = (FT_ListDevices_T)GetProcAddress(hModule,
      "FT_ListDevices");
    if (FT_ListDevices != 0)
      return FT_ListDevices(pArg1, pArg2, Flags);
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_Close(FT_HANDLE ftHandle)
{
  typedef FT_STATUS(WINAPI * FT_Close_T)(FT_HANDLE ftHandle);

  HMODULE hModule;
  FT_Close_T FT_Close;

  DumpBuffer(lastAction);

  OutputDebugStringA(
    "====================FTD2XX : FT_Close===============================");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_Close = (FT_Close_T)GetProcAddress(hModule, "FT_Close");
    if (FT_Close != 0)
      return FT_Close(ftHandle);
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_Read(FT_HANDLE ftHandle, LPVOID lpBuffer, DWORD
  dwBytesToRead, LPDWORD lpBytesReturned)
{
  typedef FT_STATUS(WINAPI * FT_Read_T)(FT_HANDLE ftHandle, LPVOID lpBuffer,
    DWORD dwBytesToRead, LPDWORD lpBytesReturned);

  HMODULE hModule;
  FT_Read_T FT_Read;
  FT_STATUS ret;
  DWORD BytesReturned;
  DWORD BytesRemaing;
  DWORD BytesCopied;

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_Read = (FT_Read_T)GetProcAddress(hModule, "FT_Read");
    if (FT_Read != 0)
    {
      if (lastAction == LAST_UNKNOWN)
        lastAction = LAST_READ;
      else if (lastAction == LAST_WRITE)
      {
        DumpBuffer(LAST_WRITE);
        lastAction = LAST_READ;
      }

      ret = FT_Read(ftHandle, lpBuffer, dwBytesToRead, lpBytesReturned);

      if (ret == FT_OK)
      {
        BytesReturned = *lpBytesReturned;
        if (readIndex + BytesReturned > READ_BUFFER_SIZE)
        {
          BytesCopied = READ_BUFFER_SIZE - readIndex;
          memcpy(readBuffer + readIndex, lpBuffer, BytesCopied);
          BytesRemaing = BytesReturned - BytesCopied; // to be buffered

          readIndex = READ_BUFFER_SIZE;
          DumpBuffer(LAST_READ); // whole read buffer

          memcpy(readBuffer, (char*)lpBuffer + BytesCopied, BytesRemaing);
          // buffer it
          readIndex = BytesRemaing;
        }
        else
        {
          memcpy(readBuffer + readIndex, lpBuffer, BytesReturned);
          // buffer it
          readIndex += BytesReturned;
        }
      }

      return ret;
    }
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_Write(FT_HANDLE ftHandle, LPVOID lpBuffer, DWORD
  dwBytesToWrite, LPDWORD lpBytesWritten)
{
  typedef FT_STATUS(WINAPI * FT_Write_T)(FT_HANDLE ftHandle, LPVOID lpBuffer,
    DWORD dwBytesToWrite, LPDWORD lpBytesWritten);

  HMODULE hModule;
  FT_Write_T FT_Write;
  FT_STATUS ret;
  DWORD BytesWritten;
  DWORD BytesRemaing;
  DWORD BytesCopied;

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_Write = (FT_Write_T)GetProcAddress(hModule, "FT_Write");
    if (FT_Write != 0)
    {
      if (lastAction == LAST_UNKNOWN)
        lastAction = LAST_WRITE;
      else if (lastAction == LAST_READ)
      {
        DumpBuffer(LAST_READ);
        lastAction = LAST_WRITE;
      }

      ret = FT_Write(ftHandle, lpBuffer, dwBytesToWrite, lpBytesWritten);
      if (ret == FT_OK)
      {
        BytesWritten = *lpBytesWritten;
        if (writeIndex + BytesWritten > WRITE_BUFFER_SIZE)
        {
          BytesCopied = WRITE_BUFFER_SIZE - writeIndex;
          memcpy(writeBuffer + writeIndex, lpBuffer, BytesCopied);
          BytesRemaing = BytesWritten - BytesCopied; // to be buffered

          writeIndex = WRITE_BUFFER_SIZE;
          DumpBuffer(LAST_WRITE); // whole write buffer

          memcpy(writeBuffer, (char*)lpBuffer + BytesCopied, BytesRemaing);
          // buffer it
          writeIndex = BytesRemaing;
        }
        else
        {
          memcpy(writeBuffer + writeIndex, lpBuffer, BytesWritten);
          writeIndex += BytesWritten;
        }
      }

      return ret;
    }
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_Read0(FT_HANDLE ftHandle, LPVOID lpBuffer, DWORD
  dwBytesToRead, LPDWORD lpBytesReturned)
{
  typedef FT_STATUS(WINAPI * FT_Read_T)(FT_HANDLE ftHandle, LPVOID lpBuffer,
    DWORD dwBytesToRead, LPDWORD lpBytesReturned);

  HMODULE hModule;
  FT_Read_T FT_Read;
  FT_STATUS ret;
  char OutputString[256];

  DWORD BytesReturned;
  char * info;
  char * buffer;

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_Read = (FT_Read_T)GetProcAddress(hModule, "FT_Read");
    if (FT_Read != 0)
    {
      ret = FT_Read(ftHandle, lpBuffer, dwBytesToRead, lpBytesReturned);

      if (ret == FT_OK)
      {
        BytesReturned = *lpBytesReturned;
        info = (char*)lpBuffer;
        buffer = (char*)&OutputString[9];

        sprintf_s(OutputString, 256, "FTD2XX : FT_Read %d bytes",
          BytesReturned);
        OutputDebugStringA(OutputString);

        sprintf_s(OutputString, 256, "FTD2XX : ");
        for (DWORD i = 0; i < ((BytesReturned + 15) >> 4); i++)
        {
          HexDump(info + (i << 4), (BytesReturned > 15) ? 16 :
            BytesReturned, buffer);
          OutputDebugStringA(OutputString);
          BytesReturned -= 16;
        }
      }
      return ret;
    }
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_Write0(FT_HANDLE ftHandle, LPVOID lpBuffer, DWORD
  dwBytesToWrite, LPDWORD lpBytesWritten)
{
  typedef FT_STATUS(WINAPI * FT_Write_T)(FT_HANDLE ftHandle, LPVOID lpBuffer,
    DWORD dwBytesToWrite, LPDWORD lpBytesWritten);

  HMODULE hModule;
  FT_Write_T FT_Write;
  FT_STATUS ret;
  char OutputString[256];

  DWORD BytesWritten;
  char * info;
  char * buffer;

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_Write = (FT_Write_T)GetProcAddress(hModule, "FT_Write");
    if (FT_Write != 0)
    {
      ret = FT_Write(ftHandle, lpBuffer, dwBytesToWrite, lpBytesWritten);
      if (ret == FT_OK)
      {
        BytesWritten = *lpBytesWritten;
        info = (char*)lpBuffer;
        buffer = (char*)&OutputString[9];

        sprintf_s(OutputString, 256, "FTD2XX : FT_Write %d bytes",
          BytesWritten);
        OutputDebugStringA(OutputString);

        sprintf_s(OutputString, 256, "FTD2XX : ");
        for (DWORD i = 0; i < ((BytesWritten + 15) >> 4); i++)
        {
          HexDump(info + (i << 4), (BytesWritten > 15) ? 16 : BytesWritten,
            buffer);

          OutputDebugStringA(OutputString);
          BytesWritten -= 16;
        }
      }

      return ret;
    }
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_IoCtl(FT_HANDLE ftHandle, DWORD dwIoControlCode, LPVOID
  lpInBuf, DWORD nInBufSize, LPVOID lpOutBuf, DWORD nOutBufSize, LPDWORD
  lpBytesReturned, LPOVERLAPPED lpOverlapped)
{
  typedef FT_STATUS(WINAPI * FT_IoCtl_T)(FT_HANDLE ftHandle, DWORD
    dwIoControlCode, LPVOID lpInBuf, DWORD nInBufSize, LPVOID lpOutBuf, DWORD
    nOutBufSize, LPDWORD lpBytesReturned, LPOVERLAPPED lpOverlapped);

  HMODULE hModule;
  FT_IoCtl_T FT_IoCtl;

  OutputDebugStringA("FTD2XX : FT_IoCtl");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_IoCtl = (FT_IoCtl_T)GetProcAddress(hModule, "FT_IoCtl");
    if (FT_IoCtl != 0)
      return FT_IoCtl(ftHandle, dwIoControlCode, lpInBuf, nInBufSize, lpOutBuf,
        nOutBufSize, lpBytesReturned, lpOverlapped);
  }

  return FT_INVALID_HANDLE;

}

FT_STATUS WINAPI FT_SetBaudRate(FT_HANDLE ftHandle, ULONG BaudRate)
{
  typedef FT_STATUS(WINAPI * FT_SetBaudRate_T)(FT_HANDLE ftHandle, ULONG
    BaudRate);

  HMODULE hModule;
  FT_SetBaudRate_T FT_SetBaudRate;
  char OutputString[256];

  sprintf_s(OutputString, 256, "FTD2XX : FT_SetBaudRate : %d bps", BaudRate);
  OutputDebugStringA(OutputString);

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_SetBaudRate = (FT_SetBaudRate_T)GetProcAddress(hModule,
      "FT_SetBaudRate");
    if (FT_SetBaudRate != 0)
      return FT_SetBaudRate(ftHandle, BaudRate);
  }

  return FT_INVALID_HANDLE;

}

FT_STATUS WINAPI FT_SetDivisor(FT_HANDLE ftHandle, USHORT Divisor)
{
  typedef FT_STATUS(WINAPI * FT_SetDivisor_T)(FT_HANDLE ftHandle, USHORT
    Divisor);

  HMODULE hModule;
  FT_SetDivisor_T FT_SetDivisor;

  OutputDebugStringA("FTD2XX : FT_SetDivisor");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_SetDivisor = (FT_SetDivisor_T)GetProcAddress(hModule, "FT_SetDivisor"
    );
    if (FT_SetDivisor != 0)
      return FT_SetDivisor(ftHandle, Divisor);
  }

  return FT_INVALID_HANDLE;

}

FT_STATUS WINAPI FT_SetDataCharacteristics(FT_HANDLE ftHandle, UCHAR
  WordLength, UCHAR StopBits, UCHAR Parity)
{
  typedef FT_STATUS(WINAPI * FT_SetDataCharacteristics_T)(FT_HANDLE ftHandle,
    UCHAR WordLength, UCHAR StopBits, UCHAR Parity);

  HMODULE hModule;
  FT_SetDataCharacteristics_T FT_SetDataCharacteristics;

  const char * parityStrings[] =
  {
    "None", "Odd", "Even", "Mask", "Space"
  };

  int lStopBits = (StopBits == 0) ? 1 : 2;

  UCHAR lWordLength = (WordLength != FT_BITS_7) ? FT_BITS_8 : FT_BITS_7;
  UCHAR lParity = (Parity > 4) ? 0 : Parity;
  char * parity = (char*)parityStrings[lParity];

  char OutputString[256];
  sprintf_s(OutputString, 256,
    "FTD2XX : FT_SetDataCharacteristics DataBit:%d, Parity:%s, StopBit:%d",
    lWordLength, parity, lStopBits);
  OutputDebugStringA(OutputString);

  //OutputDebugStringA("FTD2XX : FT_SetDataCharacteristics");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_SetDataCharacteristics = (FT_SetDataCharacteristics_T)GetProcAddress(
      hModule, "FT_SetDataCharacteristics");
    if (FT_SetDataCharacteristics != 0)
      return FT_SetDataCharacteristics(ftHandle, WordLength, StopBits, Parity)
      ;
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_SetFlowControl(FT_HANDLE ftHandle, USHORT FlowControl,
  UCHAR XonChar, UCHAR XoffChar)
{
  typedef FT_STATUS(WINAPI * FT_SetFlowControl_T)(FT_HANDLE ftHandle, USHORT
    FlowControl, UCHAR XonChar, UCHAR XoffChar);

  HMODULE hModule;
  FT_SetFlowControl_T FT_SetFlowControl;

  OutputDebugStringA("FTD2XX : FT_SetFlowControl");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_SetFlowControl = (FT_SetFlowControl_T)GetProcAddress(hModule,
      "FT_SetFlowControl");
    if (FT_SetFlowControl != 0)
      return FT_SetFlowControl(ftHandle, FlowControl, XonChar, XoffChar);
  }

  return FT_INVALID_HANDLE;

}

FT_STATUS WINAPI FT_ResetDevice(FT_HANDLE ftHandle)
{
  typedef FT_STATUS(WINAPI * FT_ResetDevice_T)(FT_HANDLE ftHandle);

  HMODULE hModule;
  FT_ResetDevice_T FT_ResetDevice;

  DumpBuffer(lastAction);

  OutputDebugStringA("FTD2XX : FT_ResetDevice");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_ResetDevice = (FT_ResetDevice_T)GetProcAddress(hModule,
      "FT_ResetDevice");
    if (FT_ResetDevice != 0)
      return FT_ResetDevice(ftHandle);
  }

  return FT_INVALID_HANDLE;

}

FT_STATUS WINAPI FT_SetDtr(FT_HANDLE ftHandle)
{
  typedef FT_STATUS(WINAPI * FT_SetDtr_T)(FT_HANDLE ftHandle);

  HMODULE hModule;
  FT_SetDtr_T FT_SetDtr;

  OutputDebugStringA("FTD2XX : FT_SetDtr");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_SetDtr = (FT_SetDtr_T)GetProcAddress(hModule, "FT_SetDtr");
    if (FT_SetDtr != 0)
      return FT_SetDtr(ftHandle);
  }

  return FT_INVALID_HANDLE;

}

FT_STATUS WINAPI FT_ClrDtr(FT_HANDLE ftHandle)
{
  typedef FT_STATUS(WINAPI * FT_ClrDtr_T)(FT_HANDLE ftHandle);

  HMODULE hModule;
  FT_ClrDtr_T FT_ClrDtr;

  OutputDebugStringA("FTD2XX : FT_ClrDtr");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_ClrDtr = (FT_ClrDtr_T)GetProcAddress(hModule, "FT_ClrDtr");
    if (FT_ClrDtr != 0)
      return FT_ClrDtr(ftHandle);
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_SetRts(FT_HANDLE ftHandle)
{
  typedef FT_STATUS(WINAPI * FT_SetRts_T)(FT_HANDLE ftHandle);

  HMODULE hModule;
  FT_SetRts_T FT_SetRts;

  OutputDebugStringA("FTD2XX : FT_SetRts");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_SetRts = (FT_SetRts_T)GetProcAddress(hModule, "FT_SetRts");
    if (FT_SetRts != 0)
      return FT_SetRts(ftHandle);
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_ClrRts(FT_HANDLE ftHandle)
{
  typedef FT_STATUS(WINAPI * FT_ClrRts_T)(FT_HANDLE ftHandle);

  HMODULE hModule;
  FT_ClrRts_T FT_ClrRts;

  OutputDebugStringA("FTD2XX : FT_ClrRts");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_ClrRts = (FT_ClrRts_T)GetProcAddress(hModule, "FT_ClrRts");
    if (FT_ClrRts != 0)
      return FT_ClrRts(ftHandle);
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_GetModemStatus(FT_HANDLE ftHandle, ULONG * pModemStatus)
{
  typedef FT_STATUS(WINAPI * FT_GetModemStatus_T)(FT_HANDLE ftHandle,
    ULONG*pModemStatus);

  HMODULE hModule;
  FT_GetModemStatus_T FT_GetModemStatus;

  OutputDebugStringA("FTD2XX : FT_GetModemStatus");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_GetModemStatus = (FT_GetModemStatus_T)GetProcAddress(hModule,
      "FT_GetModemStatus");
    if (FT_GetModemStatus != 0)
      return FT_GetModemStatus(ftHandle, pModemStatus);
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_SetChars(FT_HANDLE ftHandle, UCHAR EventChar, UCHAR
  EventCharEnabled, UCHAR ErrorChar, UCHAR ErrorCharEnabled)
{
  typedef FT_STATUS(WINAPI * FT_SetChars_T)(FT_HANDLE ftHandle, UCHAR
    EventChar, UCHAR EventCharEnabled, UCHAR ErrorChar, UCHAR ErrorCharEnabled)
    ;

  HMODULE hModule;
  FT_SetChars_T FT_SetChars;

  OutputDebugStringA("FTD2XX : FT_SetChars");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_SetChars = (FT_SetChars_T)GetProcAddress(hModule, "FT_SetChars");
    if (FT_SetChars != 0)
      return FT_SetChars(ftHandle, EventChar, EventCharEnabled, ErrorChar,
        ErrorCharEnabled);
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_Purge(FT_HANDLE ftHandle, ULONG Mask)
{
  typedef FT_STATUS(WINAPI * FT_Purge_T)(FT_HANDLE ftHandle, ULONG Mask);

  HMODULE hModule;
  FT_Purge_T FT_Purge;

  DumpBuffer(lastAction);

  OutputDebugStringA("FTD2XX : FT_Purge");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_Purge = (FT_Purge_T)GetProcAddress(hModule, "FT_Purge");
    if (FT_Purge != 0)
      return FT_Purge(ftHandle, Mask);
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_SetTimeouts(FT_HANDLE ftHandle, ULONG ReadTimeout, ULONG
  WriteTimeout)
{
  typedef FT_STATUS(WINAPI * FT_SetTimeouts_T)(FT_HANDLE ftHandle, ULONG
    ReadTimeout, ULONG WriteTimeout);

  HMODULE hModule;
  FT_SetTimeouts_T FT_SetTimeouts;

  char OutputString[256];
  sprintf_s(OutputString, 256, "FTD2XX : FT_SetTimeouts : R:%d W:%d",
    ReadTimeout, WriteTimeout);
  OutputDebugStringA(OutputString);

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_SetTimeouts = (FT_SetTimeouts_T)GetProcAddress(hModule,
      "FT_SetTimeouts");
    if (FT_SetTimeouts != 0)
      return FT_SetTimeouts(ftHandle, ReadTimeout, WriteTimeout);
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_GetQueueStatus(FT_HANDLE ftHandle, DWORD * dwRxBytes)
{
  typedef FT_STATUS(WINAPI * FT_GetQueueStatus_T)(FT_HANDLE ftHandle,
    DWORD*dwRxBytes);

  HMODULE hModule;
  FT_GetQueueStatus_T FT_GetQueueStatus;

  // OutputDebugStringA("FTD2XX : FT_GetQueueStatus");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_GetQueueStatus = (FT_GetQueueStatus_T)GetProcAddress(hModule,
      "FT_GetQueueStatus");
    if (FT_GetQueueStatus != 0)
      return FT_GetQueueStatus(ftHandle, dwRxBytes);
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_SetEventNotification(FT_HANDLE ftHandle, DWORD Mask, PVOID
  Param)
{
  typedef FT_STATUS(WINAPI * FT_SetEventNotification_T)(FT_HANDLE ftHandle,
    DWORD Mask, PVOID Param);

  HMODULE hModule;
  FT_SetEventNotification_T FT_SetEventNotification;

  OutputDebugStringA("FTD2XX : FT_SetEventNotification");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_SetEventNotification = (FT_SetEventNotification_T)GetProcAddress(
      hModule, "FT_SetEventNotification");
    if (FT_SetEventNotification != 0)
      return FT_SetEventNotification(ftHandle, Mask, Param);
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_GetStatus(FT_HANDLE ftHandle, DWORD * dwRxBytes,
  DWORD*dwTxBytes, DWORD * dwEventDWord)
{
  typedef FT_STATUS(WINAPI * FT_GetStatus_T)(FT_HANDLE ftHandle,
    DWORD*dwRxBytes, DWORD * dwTxBytes, DWORD * dwEventDWord);

  HMODULE hModule;
  FT_GetStatus_T FT_GetStatus;

  OutputDebugStringA("FTD2XX : FT_GetStatus");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_GetStatus = (FT_GetStatus_T)GetProcAddress(hModule, "FT_GetStatus");
    if (FT_GetStatus != 0)
      return FT_GetStatus(ftHandle, dwRxBytes, dwTxBytes, dwEventDWord);
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_SetBreakOn(FT_HANDLE ftHandle)
{
  typedef FT_STATUS(WINAPI * FT_SetBreakOn_T)(FT_HANDLE ftHandle);

  HMODULE hModule;
  FT_SetBreakOn_T FT_SetBreakOn;

  OutputDebugStringA("FTD2XX : FT_SetBreakOn");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_SetBreakOn = (FT_SetBreakOn_T)GetProcAddress(hModule, "FT_SetBreakOn"
    );
    if (FT_SetBreakOn != 0)
      return FT_SetBreakOn(ftHandle);
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_SetBreakOff(FT_HANDLE ftHandle)
{
  typedef FT_STATUS(WINAPI * FT_SetBreakOff_T)(FT_HANDLE ftHandle);

  HMODULE hModule;
  FT_SetBreakOff_T FT_SetBreakOff;

  OutputDebugStringA("FTD2XX : FT_SetBreakOff");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_SetBreakOff = (FT_SetBreakOff_T)GetProcAddress(hModule,
      "FT_SetBreakOff");
    if (FT_SetBreakOff != 0)
      return FT_SetBreakOff(ftHandle);
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_SetWaitMask(FT_HANDLE ftHandle, DWORD Mask)
{
  typedef FT_STATUS(WINAPI * FT_SetWaitMask_T)(FT_HANDLE ftHandle, DWORD
    Mask);

  HMODULE hModule;
  FT_SetWaitMask_T FT_SetWaitMask;

  OutputDebugStringA("FTD2XX : FT_SetWaitMask");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_SetWaitMask = (FT_SetWaitMask_T)GetProcAddress(hModule,
      "FT_SetWaitMask");
    if (FT_SetWaitMask != 0)
      return FT_SetWaitMask(ftHandle, Mask);
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_WaitOnMask(FT_HANDLE ftHandle, DWORD * Mask)
{
  typedef FT_STATUS(WINAPI * FT_WaitOnMask_T)(FT_HANDLE ftHandle, DWORD *
    Mask);

  HMODULE hModule;
  FT_WaitOnMask_T FT_WaitOnMask;

  OutputDebugStringA("FTD2XX : FT_WaitOnMask");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_WaitOnMask = (FT_WaitOnMask_T)GetProcAddress(hModule, "FT_WaitOnMask"
    );
    if (FT_WaitOnMask != 0)
      return FT_WaitOnMask(ftHandle, Mask);
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_GetEventStatus(FT_HANDLE ftHandle, DWORD * dwEventDWord)
{
  typedef FT_STATUS(WINAPI * FT_GetEventStatus_T)(FT_HANDLE ftHandle,
    DWORD*dwEventDWord);

  HMODULE hModule;
  FT_GetEventStatus_T FT_GetEventStatus;

  OutputDebugStringA("FTD2XX : FT_GetEventStatus");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_GetEventStatus = (FT_GetEventStatus_T)GetProcAddress(hModule,
      "FT_GetEventStatus");
    if (FT_GetEventStatus != 0)
      return FT_GetEventStatus(ftHandle, dwEventDWord);
  }

  return FT_INVALID_HANDLE;
}

const WORD eeprom[16] =
{
  0x0419, 0xFBE6, 0x0000, 0xD370, 0x5899, 0x0042, 0x0000, 0x0000, 0x0000,
  0x0000, 0x0000, 0x0000, 0x414C, 0x5858, 0x4F55, 0x3953
};

FT_STATUS WINAPI FT_ReadEE(FT_HANDLE ftHandle, DWORD dwWordOffset, LPWORD
  lpwValue)
{
  typedef FT_STATUS(WINAPI * FT_ReadEE_T)(FT_HANDLE ftHandle, DWORD
    dwWordOffset, LPWORD lpwValue);

  HMODULE hModule;
  FT_ReadEE_T FT_ReadEE;
  FT_STATUS ret;
  char OutputString[256];

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_ReadEE = (FT_ReadEE_T)GetProcAddress(hModule, "FT_ReadEE");
    if (FT_ReadEE != 0)
    {
      ret = FT_ReadEE(ftHandle, dwWordOffset, lpwValue);
      if ((dwWordOffset >= 0x40) && (dwWordOffset <= 0x4F))
        *lpwValue = eeprom[dwWordOffset - 0x40];

      if (ret == FT_OK)
      {
        sprintf_s(OutputString, 256, "FTD2XX : FT_ReadEE 0x%04X : 0x%04X",
          dwWordOffset, *lpwValue);
        OutputDebugStringA(OutputString);
      }
      return ret;
    }
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_WriteEE(FT_HANDLE ftHandle, DWORD dwWordOffset, WORD
  wValue)

{
  typedef FT_STATUS(WINAPI * FT_WriteEE_T)(FT_HANDLE ftHandle, DWORD
    dwWordOffset, WORD wValue);

  HMODULE hModule;
  FT_WriteEE_T FT_WriteEE;

  // OutputDebugStringA("FTD2XX : FT_WriteEE");

  char OutputString[256];
  sprintf_s(OutputString, 256, "FTD2XX : FT_WriteEE 0x%04X : 0x%04X",
    dwWordOffset, wValue);
  OutputDebugStringA(OutputString);

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_WriteEE = (FT_WriteEE_T)GetProcAddress(hModule, "FT_WriteEE");
    if (FT_WriteEE != 0)
      return FT_WriteEE(ftHandle, dwWordOffset, wValue);
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_EraseEE(FT_HANDLE ftHandle)
{
  typedef FT_STATUS(WINAPI * FT_EraseEE_T)(FT_HANDLE ftHandle);

  HMODULE hModule;
  FT_EraseEE_T FT_EraseEE;

  OutputDebugStringA("FTD2XX : FT_EraseEE");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_EraseEE = (FT_EraseEE_T)GetProcAddress(hModule, "FT_EraseEE");
    if (FT_EraseEE != 0)
      return FT_EraseEE(ftHandle);
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_EE_Program(FT_HANDLE ftHandle, PFT_PROGRAM_DATA pData)
{
  typedef FT_STATUS(WINAPI * FT_EE_Program_T)(FT_HANDLE ftHandle,
    PFT_PROGRAM_DATA pData);

  HMODULE hModule;
  FT_EE_Program_T FT_EE_Program;

  OutputDebugStringA("FTD2XX : FT_EE_Program");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_EE_Program = (FT_EE_Program_T)GetProcAddress(hModule, "FT_EE_Program"
    );
    if (FT_EE_Program != 0)
      return FT_EE_Program(ftHandle, pData);
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_EE_ProgramEx(FT_HANDLE ftHandle, PFT_PROGRAM_DATA pData,
  char * Manufacturer, char * ManufacturerId, char * Description,
  char*SerialNumber)
{
  typedef FT_STATUS(WINAPI * FT_EE_ProgramEx_T)(FT_HANDLE ftHandle,
    PFT_PROGRAM_DATA pData, char * Manufacturer, char * ManufacturerId,
    char*Description, char * SerialNumber);

  HMODULE hModule;
  FT_EE_ProgramEx_T FT_EE_ProgramEx;

  OutputDebugStringA("FTD2XX : FT_EE_ProgramEx");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_EE_ProgramEx = (FT_EE_ProgramEx_T)GetProcAddress(hModule,
      "FT_EE_ProgramEx");
    if (FT_EE_ProgramEx != 0)
      return FT_EE_ProgramEx(ftHandle, pData, Manufacturer, ManufacturerId,
        Description, SerialNumber);
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_EE_Read(FT_HANDLE ftHandle, PFT_PROGRAM_DATA pData)
{
  typedef FT_STATUS(WINAPI * FT_EE_Read_T)(FT_HANDLE ftHandle,
    PFT_PROGRAM_DATA pData);

  HMODULE hModule;
  FT_EE_Read_T FT_EE_Read;

  OutputDebugStringA("FTD2XX : FT_EE_Read");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_EE_Read = (FT_EE_Read_T)GetProcAddress(hModule, "FT_EE_Read");
    if (FT_EE_Read != 0)
      return FT_EE_Read(ftHandle, pData);
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_EE_ReadEx(FT_HANDLE ftHandle, PFT_PROGRAM_DATA pData,
  char*Manufacturer, char * ManufacturerId, char * Description, char *
  SerialNumber)
{
  typedef FT_STATUS(WINAPI * FT_EE_ReadEx_T)(FT_HANDLE ftHandle,
    PFT_PROGRAM_DATA pData, char * Manufacturer, char * ManufacturerId,
    char*Description, char * SerialNumber);

  HMODULE hModule;
  FT_EE_ReadEx_T FT_EE_ReadEx;

  OutputDebugStringA("FTD2XX : FT_EE_ReadEx");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_EE_ReadEx = (FT_EE_ReadEx_T)GetProcAddress(hModule, "FT_EE_ReadEx");
    if (FT_EE_ReadEx != 0)
      return FT_EE_ReadEx(ftHandle, pData, Manufacturer, ManufacturerId,
        Description, SerialNumber);
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_EE_UASize(FT_HANDLE ftHandle, LPDWORD lpdwSize)
{
  typedef FT_STATUS(WINAPI * FT_EE_UASize_T)(FT_HANDLE ftHandle, LPDWORD
    lpdwSize);

  HMODULE hModule;
  FT_EE_UASize_T FT_EE_UASize;

  OutputDebugStringA("FTD2XX : FT_EE_UASize");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_EE_UASize = (FT_EE_UASize_T)GetProcAddress(hModule, "FT_EE_UASize");
    if (FT_EE_UASize != 0)
      return FT_EE_UASize(ftHandle, lpdwSize);
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_EE_UAWrite(FT_HANDLE ftHandle, PUCHAR pucData, DWORD
  dwDataLen)
{
  typedef FT_STATUS(WINAPI * FT_EE_UAWrite_T)(FT_HANDLE ftHandle, PUCHAR
    pucData, DWORD dwDataLen);

  HMODULE hModule;
  FT_EE_UAWrite_T FT_EE_UAWrite;

  OutputDebugStringA("FTD2XX : FT_EE_UAWrite");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_EE_UAWrite = (FT_EE_UAWrite_T)GetProcAddress(hModule, "FT_EE_UAWrite"
    );
    if (FT_EE_UAWrite != 0)
      return FT_EE_UAWrite(ftHandle, pucData, dwDataLen);
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_EE_UARead(FT_HANDLE ftHandle, PUCHAR pucData, DWORD
  dwDataLen, LPDWORD lpdwBytesRead)
{
  typedef FT_STATUS(WINAPI * FT_EE_UARead_T)(FT_HANDLE ftHandle, PUCHAR
    pucData, DWORD dwDataLen, LPDWORD lpdwBytesRead);

  HMODULE hModule;
  FT_EE_UARead_T FT_EE_UARead;

  OutputDebugStringA("FTD2XX : FT_EE_UARead");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_EE_UARead = (FT_EE_UARead_T)GetProcAddress(hModule, "FT_EE_UARead");
    if (FT_EE_UARead != 0)
      return FT_EE_UARead(ftHandle, pucData, dwDataLen, lpdwBytesRead);
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_EEPROM_Read(FT_HANDLE ftHandle, void * eepromData, DWORD
  eepromDataSize, char * Manufacturer, char * ManufacturerId, char *
  Description, char * SerialNumber)
{
  typedef FT_STATUS(WINAPI * FT_EEPROM_Read_T)(FT_HANDLE ftHandle,
    void*eepromData, DWORD eepromDataSize, char * Manufacturer, char *
    ManufacturerId, char * Description, char * SerialNumber);

  HMODULE hModule;
  FT_EEPROM_Read_T FT_EEPROM_Read;

  OutputDebugStringA("FTD2XX : FT_EEPROM_Read");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_EEPROM_Read = (FT_EEPROM_Read_T)GetProcAddress(hModule,
      "FT_EEPROM_Read");
    if (FT_EEPROM_Read != 0)
      return FT_EEPROM_Read(ftHandle, eepromData, eepromDataSize, Manufacturer,
        ManufacturerId, Description, SerialNumber);
  }

  return FT_INVALID_HANDLE;

}

FT_STATUS WINAPI FT_EEPROM_Program(FT_HANDLE ftHandle, void * eepromData,
  DWORD eepromDataSize, char * Manufacturer, char * ManufacturerId, char *
  Description, char * SerialNumber)
{
  typedef FT_STATUS(WINAPI * FT_EEPROM_Program_T)(FT_HANDLE ftHandle,
    void*eepromData, DWORD eepromDataSize, char * Manufacturer, char *
    ManufacturerId, char * Description, char * SerialNumber);

  HMODULE hModule;
  FT_EEPROM_Program_T FT_EEPROM_Program;

  OutputDebugStringA("FTD2XX : FT_EEPROM_Program");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_EEPROM_Program = (FT_EEPROM_Program_T)GetProcAddress(hModule,
      "FT_EEPROM_Program");
    if (FT_EEPROM_Program != 0)
      return FT_EEPROM_Program(ftHandle, eepromData, eepromDataSize,
        Manufacturer, ManufacturerId, Description, SerialNumber);
  }

  return FT_INVALID_HANDLE;

}

FT_STATUS WINAPI FT_SetLatencyTimer(FT_HANDLE ftHandle, UCHAR ucLatency)
{
  typedef FT_STATUS(WINAPI * FT_SetLatencyTimer_T)(FT_HANDLE ftHandle, UCHAR
    ucLatency);

  HMODULE hModule;
  FT_SetLatencyTimer_T FT_SetLatencyTimer;

  OutputDebugStringA("FTD2XX : FT_SetLatencyTimer");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_SetLatencyTimer = (FT_SetLatencyTimer_T)GetProcAddress(hModule,
      "FT_SetLatencyTimer");
    if (FT_SetLatencyTimer != 0)
      return FT_SetLatencyTimer(ftHandle, ucLatency);
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_GetLatencyTimer(FT_HANDLE ftHandle, PUCHAR pucLatency)
{
  typedef FT_STATUS(WINAPI * FT_GetLatencyTimer_T)(FT_HANDLE ftHandle,
    PUCHAR pucLatency);

  HMODULE hModule;
  FT_GetLatencyTimer_T FT_GetLatencyTimer;

  OutputDebugStringA("FTD2XX : FT_GetLatencyTimer");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_GetLatencyTimer = (FT_GetLatencyTimer_T)GetProcAddress(hModule,
      "FT_GetLatencyTimer");
    if (FT_GetLatencyTimer != 0)
      return FT_GetLatencyTimer(ftHandle, pucLatency);
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_SetBitMode(FT_HANDLE ftHandle, UCHAR ucMask, UCHAR
  ucEnable)

{
  typedef FT_STATUS(WINAPI * FT_SetBitMode_T)(FT_HANDLE ftHandle, UCHAR
    ucMask, UCHAR ucEnable);

  HMODULE hModule;
  FT_SetBitMode_T FT_SetBitMode;

  OutputDebugStringA("FTD2XX : FT_SetBitMode");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_SetBitMode = (FT_SetBitMode_T)GetProcAddress(hModule, "FT_SetBitMode"
    );
    if (FT_SetBitMode != 0)
      return FT_SetBitMode(ftHandle, ucMask, ucEnable);
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_GetBitMode(FT_HANDLE ftHandle, PUCHAR pucMode)
{
  typedef FT_STATUS(WINAPI * FT_GetBitMode_T)(FT_HANDLE ftHandle, PUCHAR
    pucMode);

  HMODULE hModule;
  FT_GetBitMode_T FT_GetBitMode;

  OutputDebugStringA("FTD2XX : FT_GetBitMode");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_GetBitMode = (FT_GetBitMode_T)GetProcAddress(hModule, "FT_GetBitMode"
    );
    if (FT_GetBitMode != 0)
      return FT_GetBitMode(ftHandle, pucMode);
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_SetUSBParameters(FT_HANDLE ftHandle, ULONG
  ulInTransferSize, ULONG ulOutTransferSize)
{
  typedef FT_STATUS(WINAPI * FT_SetUSBParameters_T)(FT_HANDLE ftHandle,
    ULONG ulInTransferSize, ULONG ulOutTransferSize);

  HMODULE hModule;
  FT_SetUSBParameters_T FT_SetUSBParameters;

  OutputDebugStringA("FTD2XX : FT_SetUSBParameters");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_SetUSBParameters = (FT_SetUSBParameters_T)GetProcAddress(hModule,
      "FT_SetUSBParameters");
    if (FT_SetUSBParameters != 0)
      return FT_SetUSBParameters(ftHandle, ulInTransferSize, ulOutTransferSize
      );
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_SetDeadmanTimeout(FT_HANDLE ftHandle, ULONG
  ulDeadmanTimeout)
{
  typedef FT_STATUS(WINAPI * FT_SetDeadmanTimeout_T)(FT_HANDLE ftHandle,
    ULONG ulDeadmanTimeout);

  HMODULE hModule;
  FT_SetDeadmanTimeout_T FT_SetDeadmanTimeout;

  OutputDebugStringA("FTD2XX : FT_SetDeadmanTimeout");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_SetDeadmanTimeout = (FT_SetDeadmanTimeout_T)GetProcAddress(hModule,
      "FT_SetDeadmanTimeout");
    if (FT_SetDeadmanTimeout != 0)
      return FT_SetDeadmanTimeout(ftHandle, ulDeadmanTimeout);
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_GetDeviceInfo(FT_HANDLE ftHandle, FT_DEVICE * lpftDevice,
  LPDWORD lpdwID, PCHAR SerialNumber, PCHAR Description, LPVOID Dummy)
{
  typedef FT_STATUS(WINAPI * FT_GetDeviceInfo_T)(FT_HANDLE ftHandle,
    FT_DEVICE*lpftDevice, LPDWORD lpdwID, PCHAR SerialNumber, PCHAR Description,
    LPVOID Dummy);

  HMODULE hModule;
  FT_GetDeviceInfo_T FT_GetDeviceInfo;

  OutputDebugStringA("FTD2XX : FT_GetDeviceInfo");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_GetDeviceInfo = (FT_GetDeviceInfo_T)GetProcAddress(hModule,
      "FT_GetDeviceInfo");
    if (FT_GetDeviceInfo != 0)
      return FT_GetDeviceInfo(ftHandle, lpftDevice, lpdwID, SerialNumber,
        Description, Dummy);
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_StopInTask(FT_HANDLE ftHandle)
{
  typedef FT_STATUS(WINAPI * FT_StopInTask_T)(FT_HANDLE ftHandle);

  HMODULE hModule;
  FT_StopInTask_T FT_StopInTask;

  OutputDebugStringA("FTD2XX : FT_StopInTask");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_StopInTask = (FT_StopInTask_T)GetProcAddress(hModule, "FT_StopInTask"
    );
    if (FT_StopInTask != 0)
      return FT_StopInTask(ftHandle);
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_RestartInTask(FT_HANDLE ftHandle)
{
  typedef FT_STATUS(WINAPI * FT_RestartInTask_T)(FT_HANDLE ftHandle);

  HMODULE hModule;
  FT_RestartInTask_T FT_RestartInTask;

  OutputDebugStringA("FTD2XX : FT_RestartInTask");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_RestartInTask = (FT_RestartInTask_T)GetProcAddress(hModule,
      "FT_RestartInTask");
    if (FT_RestartInTask != 0)
      return FT_RestartInTask(ftHandle);
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_SetResetPipeRetryCount(FT_HANDLE ftHandle, DWORD dwCount)
{
  typedef FT_STATUS(WINAPI * FT_SetResetPipeRetryCount_T)(FT_HANDLE ftHandle,
    DWORD dwCount);

  HMODULE hModule;
  FT_SetResetPipeRetryCount_T FT_SetResetPipeRetryCount;

  OutputDebugStringA("FTD2XX : FT_SetResetPipeRetryCount");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_SetResetPipeRetryCount = (FT_SetResetPipeRetryCount_T)GetProcAddress(
      hModule, "FT_SetResetPipeRetryCount");
    if (FT_SetResetPipeRetryCount != 0)
      return FT_SetResetPipeRetryCount(ftHandle, dwCount);
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_ResetPort(FT_HANDLE ftHandle)
{
  typedef FT_STATUS(WINAPI * FT_ResetPort_T)(FT_HANDLE ftHandle);

  HMODULE hModule;
  FT_ResetPort_T FT_ResetPort;

  OutputDebugStringA("FTD2XX : FT_ResetPort");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_ResetPort = (FT_ResetPort_T)GetProcAddress(hModule, "FT_ResetPort");
    if (FT_ResetPort != 0)
      return FT_ResetPort(ftHandle);
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_CyclePort(FT_HANDLE ftHandle)
{
  typedef FT_STATUS(WINAPI * FT_CyclePort_T)(FT_HANDLE ftHandle);

  HMODULE hModule;
  FT_CyclePort_T FT_CyclePort;

  OutputDebugStringA("FTD2XX : FT_CyclePort");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_CyclePort = (FT_CyclePort_T)GetProcAddress(hModule, "FT_CyclePort");
    if (FT_CyclePort != 0)
      return FT_CyclePort(ftHandle);
  }

  return FT_INVALID_HANDLE;
}

//
// Win32-type functions
//

FT_HANDLE WINAPI FT_W32_CreateFile(LPCTSTR lpszName, DWORD dwAccess, DWORD
  dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreate,
  DWORD dwAttrsAndFlags, HANDLE hTemplate)
{
  typedef FT_HANDLE(WINAPI * FT_W32_CreateFile_T)(LPCTSTR lpszName, DWORD
    dwAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreate, DWORD dwAttrsAndFlags, HANDLE hTemplate);

  HMODULE hModule;
  FT_W32_CreateFile_T FT_W32_CreateFile;

  OutputDebugStringA("FTD2XX : FT_W32_CreateFile");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_W32_CreateFile = (FT_W32_CreateFile_T)GetProcAddress(hModule,
      "FT_W32_CreateFile");
    if (FT_W32_CreateFile != 0)
      return FT_W32_CreateFile(lpszName, dwAccess, dwShareMode,
        lpSecurityAttributes, dwCreate, dwAttrsAndFlags, hTemplate);
  }

  return NULL;
}

BOOL WINAPI FT_W32_CloseHandle(FT_HANDLE ftHandle)
{
  typedef BOOL(WINAPI * FT_W32_CloseHandle_T)(FT_HANDLE ftHandle);

  HMODULE hModule;
  FT_W32_CloseHandle_T FT_W32_CloseHandle;

  OutputDebugStringA("FTD2XX : FT_W32_CloseHandle");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_W32_CloseHandle = (FT_W32_CloseHandle_T)GetProcAddress(hModule,
      "FT_W32_CloseHandle");
    if (FT_W32_CloseHandle != 0)
      return FT_W32_CloseHandle(ftHandle);
  }

  return FALSE;
}

BOOL WINAPI FT_W32_ReadFile(FT_HANDLE ftHandle, LPVOID lpBuffer, DWORD
  nBufferSize, LPDWORD lpBytesReturned, LPOVERLAPPED lpOverlapped)
{
  typedef BOOL(WINAPI * FT_W32_ReadFile_T)(FT_HANDLE ftHandle, LPVOID
    lpBuffer, DWORD nBufferSize, LPDWORD lpBytesReturned, LPOVERLAPPED
    lpOverlapped);

  HMODULE hModule;
  FT_W32_ReadFile_T FT_W32_ReadFile;

  OutputDebugStringA("FTD2XX : FT_W32_ReadFile");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_W32_ReadFile = (FT_W32_ReadFile_T)GetProcAddress(hModule,
      "FT_W32_ReadFile");
    if (FT_W32_ReadFile != 0)
      return FT_W32_ReadFile(ftHandle, lpBuffer, nBufferSize, lpBytesReturned,
        lpOverlapped);
  }

  return FALSE;
}

BOOL WINAPI FT_W32_WriteFile(FT_HANDLE ftHandle, LPVOID lpBuffer, DWORD
  nBufferSize, LPDWORD lpBytesWritten, LPOVERLAPPED lpOverlapped)
{
  typedef BOOL(WINAPI * FT_W32_WriteFile_T)(FT_HANDLE ftHandle, LPVOID
    lpBuffer, DWORD nBufferSize, LPDWORD lpBytesWritten, LPOVERLAPPED
    lpOverlapped);

  HMODULE hModule;
  FT_W32_WriteFile_T FT_W32_WriteFile;

  OutputDebugStringA("FTD2XX : FT_W32_WriteFile");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_W32_WriteFile = (FT_W32_WriteFile_T)GetProcAddress(hModule,
      "FT_W32_WriteFile");
    if (FT_W32_WriteFile != 0)
      return FT_W32_WriteFile(ftHandle, lpBuffer, nBufferSize, lpBytesWritten,
        lpOverlapped);
  }

  return FALSE;
}

DWORD WINAPI FT_W32_GetLastError(FT_HANDLE ftHandle)
{
  typedef DWORD(WINAPI * FT_W32_GetLastError_T)(FT_HANDLE ftHandle);

  HMODULE hModule;
  FT_W32_GetLastError_T FT_W32_GetLastError;

  OutputDebugStringA("FTD2XX : FT_W32_GetLastError");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_W32_GetLastError = (FT_W32_GetLastError_T)GetProcAddress(hModule,
      "FT_W32_GetLastError");
    if (FT_W32_GetLastError != 0)
      return FT_W32_GetLastError(ftHandle);
  }

  return FT_OK;
}

BOOL WINAPI FT_W32_GetOverlappedResult(FT_HANDLE ftHandle, LPOVERLAPPED
  lpOverlapped, LPDWORD lpdwBytesTransferred, BOOL bWait)
{
  typedef BOOL(WINAPI * FT_W32_GetOverlappedResult_T)(FT_HANDLE ftHandle,
    LPOVERLAPPED lpOverlapped, LPDWORD lpdwBytesTransferred, BOOL bWait);

  HMODULE hModule;
  FT_W32_GetOverlappedResult_T FT_W32_GetOverlappedResult;

  OutputDebugStringA("FTD2XX : FT_W32_GetOverlappedResult");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_W32_GetOverlappedResult = (FT_W32_GetOverlappedResult_T)GetProcAddress
    (hModule, "FT_W32_GetOverlappedResult");
    if (FT_W32_GetOverlappedResult != 0)
      return FT_W32_GetOverlappedResult(ftHandle, lpOverlapped,
        lpdwBytesTransferred, bWait);
  }

  return FALSE;
}

BOOL WINAPI FT_W32_CancelIo(FT_HANDLE ftHandle)
{
  typedef BOOL(WINAPI * FT_W32_CancelIo_T)(FT_HANDLE ftHandle);

  HMODULE hModule;
  FT_W32_CancelIo_T FT_W32_CancelIo;

  OutputDebugStringA("FTD2XX : FT_W32_CancelIo");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_W32_CancelIo = (FT_W32_CancelIo_T)GetProcAddress(hModule,
      "FT_W32_CancelIo");
    if (FT_W32_CancelIo != 0)
      return FT_W32_CancelIo(ftHandle);
  }

  return FALSE;
}

BOOL WINAPI FT_W32_ClearCommBreak(FT_HANDLE ftHandle)
{
  typedef BOOL(WINAPI * FT_W32_ClearCommBreak_T)(FT_HANDLE ftHandle);

  HMODULE hModule;
  FT_W32_ClearCommBreak_T FT_W32_ClearCommBreak;

  OutputDebugStringA("FTD2XX : FT_W32_ClearCommBreak");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_W32_ClearCommBreak = (FT_W32_ClearCommBreak_T)GetProcAddress(hModule,
      "FT_W32_ClearCommBreak");
    if (FT_W32_ClearCommBreak != 0)
      return FT_W32_ClearCommBreak(ftHandle);
  }

  return FALSE;
}

BOOL WINAPI FT_W32_ClearCommError(FT_HANDLE ftHandle, LPDWORD lpdwErrors,
  LPFTCOMSTAT lpftComstat)
{
  typedef BOOL(WINAPI * FT_W32_ClearCommError_T)(FT_HANDLE ftHandle, LPDWORD
    lpdwErrors, LPFTCOMSTAT lpftComstat);

  HMODULE hModule;
  FT_W32_ClearCommError_T FT_W32_ClearCommError;

  OutputDebugStringA("FTD2XX : FT_W32_ClearCommError");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_W32_ClearCommError = (FT_W32_ClearCommError_T)GetProcAddress(hModule,
      "FT_W32_ClearCommError");
    if (FT_W32_ClearCommError != 0)
      return FT_W32_ClearCommError(ftHandle, lpdwErrors, lpftComstat);
  }

  return FALSE;
}

BOOL WINAPI FT_W32_EscapeCommFunction(FT_HANDLE ftHandle, DWORD dwFunc)
{
  typedef BOOL(WINAPI * FT_W32_EscapeCommFunction_T)(FT_HANDLE ftHandle,
    DWORD dwFunc);

  HMODULE hModule;
  FT_W32_EscapeCommFunction_T FT_W32_EscapeCommFunction;

  OutputDebugStringA("FTD2XX : FT_W32_EscapeCommFunction");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_W32_EscapeCommFunction = (FT_W32_EscapeCommFunction_T)GetProcAddress(
      hModule, "FT_W32_EscapeCommFunction");
    if (FT_W32_EscapeCommFunction != 0)
      return FT_W32_EscapeCommFunction(ftHandle, dwFunc);
  }

  return FALSE;
}

BOOL WINAPI FT_W32_GetCommModemStatus(FT_HANDLE ftHandle, LPDWORD
  lpdwModemStatus)
{
  typedef BOOL(WINAPI * FT_W32_GetCommModemStatus_T)(FT_HANDLE ftHandle,
    LPDWORD lpdwModemStatus);

  HMODULE hModule;
  FT_W32_GetCommModemStatus_T FT_W32_GetCommModemStatus;

  OutputDebugStringA("FTD2XX : FT_W32_GetCommModemStatus");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_W32_GetCommModemStatus = (FT_W32_GetCommModemStatus_T)GetProcAddress(
      hModule, "FT_W32_GetCommModemStatus");
    if (FT_W32_GetCommModemStatus != 0)
      return FT_W32_GetCommModemStatus(ftHandle, lpdwModemStatus);
  }

  return FALSE;
}

BOOL WINAPI FT_W32_GetCommState(FT_HANDLE ftHandle, LPFTDCB lpftDcb)
{
  typedef BOOL(WINAPI * FT_W32_GetCommState_T)(FT_HANDLE ftHandle, LPFTDCB
    lpftDcb);

  HMODULE hModule;
  FT_W32_GetCommState_T FT_W32_GetCommState;

  OutputDebugStringA("FTD2XX : FT_W32_GetCommState");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_W32_GetCommState = (FT_W32_GetCommState_T)GetProcAddress(hModule,
      "FT_W32_GetCommState");
    if (FT_W32_GetCommState != 0)
      return FT_W32_GetCommState(ftHandle, lpftDcb);
  }

  return FALSE;
}

BOOL WINAPI FT_W32_GetCommTimeouts(FT_HANDLE ftHandle, FTTIMEOUTS * pTimeouts)
{
  typedef BOOL(WINAPI * FT_W32_GetCommTimeouts_T)(FT_HANDLE ftHandle,
    FTTIMEOUTS*pTimeouts);

  HMODULE hModule;
  FT_W32_GetCommTimeouts_T FT_W32_GetCommTimeouts;

  OutputDebugStringA("FTD2XX : FT_W32_GetCommTimeouts");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_W32_GetCommTimeouts = (FT_W32_GetCommTimeouts_T)GetProcAddress(
      hModule, "FT_W32_GetCommTimeouts");
    if (FT_W32_GetCommTimeouts != 0)
      return FT_W32_GetCommTimeouts(ftHandle, pTimeouts);
  }

  return FALSE;
}

BOOL WINAPI FT_W32_PurgeComm(FT_HANDLE ftHandle, DWORD dwMask)
{
  typedef BOOL(WINAPI * FT_W32_PurgeComm_T)(FT_HANDLE ftHandle, DWORD dwMask
    );

  HMODULE hModule;
  FT_W32_PurgeComm_T FT_W32_PurgeComm;

  OutputDebugStringA("FTD2XX : FT_W32_PurgeComm");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_W32_PurgeComm = (FT_W32_PurgeComm_T)GetProcAddress(hModule,
      "FT_W32_PurgeComm");
    if (FT_W32_PurgeComm != 0)
      return FT_W32_PurgeComm(ftHandle, dwMask);
  }

  return FT_INVALID_HANDLE;
}

BOOL WINAPI FT_W32_SetCommBreak(FT_HANDLE ftHandle)
{
  typedef BOOL(WINAPI * FT_W32_SetCommBreak_T)(FT_HANDLE ftHandle);

  HMODULE hModule;
  FT_W32_SetCommBreak_T FT_W32_SetCommBreak;

  OutputDebugStringA("FTD2XX : FT_W32_SetCommBreak");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_W32_SetCommBreak = (FT_W32_SetCommBreak_T)GetProcAddress(hModule,
      "FT_W32_SetCommBreak");
    if (FT_W32_SetCommBreak != 0)
      return FT_W32_SetCommBreak(ftHandle);
  }

  return FALSE;
}

BOOL WINAPI FT_W32_SetCommMask(FT_HANDLE ftHandle, ULONG ulEventMask)
{
  typedef BOOL(WINAPI * FT_W32_SetCommMask_T)(FT_HANDLE ftHandle, ULONG
    ulEventMask);

  HMODULE hModule;
  FT_W32_SetCommMask_T FT_W32_SetCommMask;

  OutputDebugStringA("FTD2XX : FT_W32_SetCommMask");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_W32_SetCommMask = (FT_W32_SetCommMask_T)GetProcAddress(hModule,
      "FT_W32_SetCommMask");
    if (FT_W32_SetCommMask != 0)
      return FT_W32_SetCommMask(ftHandle, ulEventMask);
  }

  return FALSE;
}

BOOL WINAPI FT_W32_GetCommMask(FT_HANDLE ftHandle, LPDWORD lpdwEventMask)
{
  typedef BOOL(WINAPI * FT_W32_GetCommMask_T)(FT_HANDLE ftHandle, LPDWORD
    lpdwEventMask);

  HMODULE hModule;
  FT_W32_GetCommMask_T FT_W32_GetCommMask;

  OutputDebugStringA("FTD2XX : FT_W32_GetCommMask");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_W32_GetCommMask = (FT_W32_GetCommMask_T)GetProcAddress(hModule,
      "FT_W32_GetCommMask");
    if (FT_W32_GetCommMask != 0)
      return FT_W32_GetCommMask(ftHandle, lpdwEventMask);
  }

  return FALSE;
}

BOOL WINAPI FT_W32_SetCommState(FT_HANDLE ftHandle, LPFTDCB lpftDcb)
{
  typedef BOOL(WINAPI * FT_W32_SetCommState_T)(FT_HANDLE ftHandle, LPFTDCB
    lpftDcb);

  HMODULE hModule;
  FT_W32_SetCommState_T FT_W32_SetCommState;

  OutputDebugStringA("FTD2XX : FT_W32_SetCommState");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_W32_SetCommState = (FT_W32_SetCommState_T)GetProcAddress(hModule,
      "FT_W32_SetCommState");
    if (FT_W32_SetCommState != 0)
      return FT_W32_SetCommState(ftHandle, lpftDcb);
  }

  return FT_INVALID_HANDLE;
}

BOOL WINAPI FT_W32_SetCommTimeouts(FT_HANDLE ftHandle, FTTIMEOUTS * pTimeouts)
{
  typedef BOOL(WINAPI * FT_W32_SetCommTimeouts_T)(FT_HANDLE ftHandle,
    FTTIMEOUTS*pTimeouts);

  HMODULE hModule;
  FT_W32_SetCommTimeouts_T FT_W32_SetCommTimeouts;

  OutputDebugStringA("FTD2XX : FT_W32_SetCommTimeouts");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_W32_SetCommTimeouts = (FT_W32_SetCommTimeouts_T)GetProcAddress(
      hModule, "FT_W32_SetCommTimeouts");
    if (FT_W32_SetCommTimeouts != 0)
      return FT_W32_SetCommTimeouts(ftHandle, pTimeouts);
  }

  return FALSE;
}

BOOL WINAPI FT_W32_SetupComm(FT_HANDLE ftHandle, DWORD dwReadBufferSize, DWORD
  dwWriteBufferSize)
{
  typedef BOOL(WINAPI * FT_W32_SetupComm_T)(FT_HANDLE ftHandle, DWORD
    dwReadBufferSize, DWORD dwWriteBufferSize);

  HMODULE hModule;
  FT_W32_SetupComm_T FT_W32_SetupComm;

  OutputDebugStringA("FTD2XX : FT_W32_SetupComm");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_W32_SetupComm = (FT_W32_SetupComm_T)GetProcAddress(hModule,
      "FT_W32_SetupComm");
    if (FT_W32_SetupComm != 0)
      return FT_W32_SetupComm(ftHandle, dwReadBufferSize, dwWriteBufferSize);
  }

  return FALSE;
}

BOOL WINAPI FT_W32_WaitCommEvent(FT_HANDLE ftHandle, PULONG pulEvent,
  LPOVERLAPPED lpOverlapped)
{
  typedef BOOL(WINAPI * FT_W32_WaitCommEvent_T)(FT_HANDLE ftHandle, PULONG
    pulEvent, LPOVERLAPPED lpOverlapped);

  HMODULE hModule;
  FT_W32_WaitCommEvent_T FT_W32_WaitCommEvent;

  OutputDebugStringA("FTD2XX : FT_W32_WaitCommEvent");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_W32_WaitCommEvent = (FT_W32_WaitCommEvent_T)GetProcAddress(hModule,
      "FT_W32_WaitCommEvent");
    if (FT_W32_WaitCommEvent != 0)
      return FT_W32_WaitCommEvent(ftHandle, pulEvent, lpOverlapped);
  }

  return FALSE;

}

FT_STATUS WINAPI FT_CreateDeviceInfoList(LPDWORD lpdwNumDevs)
{
  typedef FT_STATUS(WINAPI * FT_CreateDeviceInfoList_T)(LPDWORD lpdwNumDevs)
    ;

  HMODULE hModule;
  FT_CreateDeviceInfoList_T FT_CreateDeviceInfoList;

  OutputDebugStringA("FTD2XX : FT_CreateDeviceInfoList");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_CreateDeviceInfoList = (FT_CreateDeviceInfoList_T)GetProcAddress(
      hModule, "FT_CreateDeviceInfoList");
    if (FT_CreateDeviceInfoList != 0)
      return FT_CreateDeviceInfoList(lpdwNumDevs);
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_GetDeviceInfoList(FT_DEVICE_LIST_INFO_NODE * pDest,
  LPDWORD lpdwNumDevs)
{
  typedef FT_STATUS(WINAPI * FT_GetDeviceInfoList_T)(
    FT_DEVICE_LIST_INFO_NODE*pDest, LPDWORD lpdwNumDevs);

  HMODULE hModule;
  FT_GetDeviceInfoList_T FT_GetDeviceInfoList;

  OutputDebugStringA("FTD2XX : FT_GetDeviceInfoList");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_GetDeviceInfoList = (FT_GetDeviceInfoList_T)GetProcAddress(hModule,
      "FT_GetDeviceInfoList");
    if (FT_GetDeviceInfoList != 0)
      return FT_GetDeviceInfoList(pDest, lpdwNumDevs);
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_GetDeviceInfoDetail(DWORD dwIndex, LPDWORD lpdwFlags,
  LPDWORD lpdwType, LPDWORD lpdwID, LPDWORD lpdwLocId, LPVOID lpSerialNumber,
  LPVOID lpDescription, FT_HANDLE * pftHandle)
{
  typedef FT_STATUS(WINAPI * FT_GetDeviceInfoDetail_T)(DWORD dwIndex,
    LPDWORD lpdwFlags, LPDWORD lpdwType, LPDWORD lpdwID, LPDWORD lpdwLocId,
    LPVOID lpSerialNumber, LPVOID lpDescription, FT_HANDLE * pftHandle);

  HMODULE hModule;
  FT_GetDeviceInfoDetail_T FT_GetDeviceInfoDetail;

  OutputDebugStringA("FTD2XX : FT_GetDeviceInfoDetail");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_GetDeviceInfoDetail = (FT_GetDeviceInfoDetail_T)GetProcAddress(
      hModule, "FT_GetDeviceInfoDetail");
    if (FT_GetDeviceInfoDetail != 0)
      return FT_GetDeviceInfoDetail(dwIndex, lpdwFlags, lpdwType, lpdwID,
        lpdwLocId, lpSerialNumber, lpDescription, pftHandle);
  }

  return FT_INVALID_HANDLE;
}

//
// Version information
//

FT_STATUS WINAPI FT_GetDriverVersion(FT_HANDLE ftHandle, LPDWORD lpdwVersion)
{
  typedef FT_STATUS(WINAPI * FT_GetDriverVersion_T)(FT_HANDLE ftHandle,
    LPDWORD lpdwVersion);

  HMODULE hModule;
  FT_GetDriverVersion_T FT_GetDriverVersion;

  char OutputString[256];
  // OutputDebugStringA("FTD2XX : FT_GetDriverVersion");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_GetDriverVersion = (FT_GetDriverVersion_T)GetProcAddress(hModule,
      "FT_GetDriverVersion");
    if (FT_GetDriverVersion != 0)
    {
      FT_STATUS ret = FT_GetDriverVersion(ftHandle, lpdwVersion);
      if (ret == FT_OK)
      {
        sprintf_s(OutputString, 256, "FTD2XX : FT_GetDriverVersion %d.%d.%d",
          ((*lpdwVersion) >> 16) & 0xFFFF, ((*lpdwVersion) >> 8) & 0xFF, ((
            *lpdwVersion) >> 0) & 0xFF);
        OutputDebugStringA(OutputString);
      }
      return ret;

    }
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_GetLibraryVersion(LPDWORD lpdwVersion)
{
  typedef FT_STATUS(WINAPI * FT_GetLibraryVersion_T)(LPDWORD lpdwVersion);

  HMODULE hModule;
  FT_GetLibraryVersion_T FT_GetLibraryVersion;

  char OutputString[256];
  // OutputDebugStringA("FTD2XX : FT_GetLibraryVersion");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_GetLibraryVersion = (FT_GetLibraryVersion_T)GetProcAddress(hModule,
      "FT_GetLibraryVersion");
    if (FT_GetLibraryVersion != 0)
    {
      FT_STATUS ret = FT_GetLibraryVersion(lpdwVersion);
      if (ret == FT_OK)
      {
        sprintf_s(OutputString, 256, "FTD2XX : FT_GetLibraryVersion %d.%d.%d",
          ((*lpdwVersion) >> 16) & 0xFFFF, ((*lpdwVersion) >> 8) & 0xFF, ((
            *lpdwVersion) >> 0) & 0xFF);
        OutputDebugStringA(OutputString);
      }
      return ret;
    }
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_Rescan(void)
{
  typedef FT_STATUS(WINAPI * FT_Rescan_T)(void);

  HMODULE hModule;
  FT_Rescan_T FT_Rescan;

  OutputDebugStringA("FTD2XX : FT_Rescan");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_Rescan = (FT_Rescan_T)GetProcAddress(hModule, "FT_Rescan");
    if (FT_Rescan != 0)
      return FT_Rescan();
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_Reload(WORD wVid, WORD wPid)
{
  typedef FT_STATUS(WINAPI * FT_Reload_T)(WORD wVid, WORD wPid);

  HMODULE hModule;
  FT_Reload_T FT_Reload;

  OutputDebugStringA("FTD2XX : FT_Reload");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_Reload = (FT_Reload_T)GetProcAddress(hModule, "FT_Reload");
    if (FT_Reload != 0)
      return FT_Reload(wVid, wPid);
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_GetComPortNumber(FT_HANDLE ftHandle, LPLONG
  lpdwComPortNumber)
{
  typedef FT_STATUS(WINAPI * FT_GetComPortNumber_T)(FT_HANDLE ftHandle,
    LPLONG lpdwComPortNumber);

  HMODULE hModule;
  FT_GetComPortNumber_T FT_GetComPortNumber;

  OutputDebugStringA("FTD2XX : FT_GetComPortNumber");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_GetComPortNumber = (FT_GetComPortNumber_T)GetProcAddress(hModule,
      "FT_GetComPortNumber");
    if (FT_GetComPortNumber != 0)
      return FT_GetComPortNumber(ftHandle, lpdwComPortNumber);
  }

  return FT_INVALID_HANDLE;
}

//
// FT232H additional EEPROM functions
//

FT_STATUS WINAPI FT_EE_ReadConfig(FT_HANDLE ftHandle, UCHAR ucAddress, PUCHAR
  pucValue)
{
  typedef FT_STATUS(WINAPI * FT_EE_ReadConfig_T)(FT_HANDLE ftHandle, UCHAR
    ucAddress, PUCHAR pucValue);

  HMODULE hModule;
  FT_EE_ReadConfig_T FT_EE_ReadConfig;

  OutputDebugStringA("FTD2XX : FT_EE_ReadConfig");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_EE_ReadConfig = (FT_EE_ReadConfig_T)GetProcAddress(hModule,
      "FT_EE_ReadConfig");
    if (FT_EE_ReadConfig != 0)
      return FT_EE_ReadConfig(ftHandle, ucAddress, pucValue);
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_EE_WriteConfig(FT_HANDLE ftHandle, UCHAR ucAddress, UCHAR
  ucValue)
{
  typedef FT_STATUS(WINAPI * FT_EE_WriteConfig_T)(FT_HANDLE ftHandle, UCHAR
    ucAddress, UCHAR ucValue);

  HMODULE hModule;
  FT_EE_WriteConfig_T FT_EE_WriteConfig;

  OutputDebugStringA("FTD2XX : FT_EE_WriteConfig");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_EE_WriteConfig = (FT_EE_WriteConfig_T)GetProcAddress(hModule,
      "FT_EE_WriteConfig");
    if (FT_EE_WriteConfig != 0)
      return FT_EE_WriteConfig(ftHandle, ucAddress, ucValue);
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_EE_ReadECC(FT_HANDLE ftHandle, UCHAR ucOption, LPWORD
  lpwValue)
{
  typedef FT_STATUS(WINAPI * FT_EE_ReadECC_T)(FT_HANDLE ftHandle, UCHAR
    ucOption, LPWORD lpwValue);

  HMODULE hModule;
  FT_EE_ReadECC_T FT_EE_ReadECC;

  OutputDebugStringA("FTD2XX : FT_EE_ReadECC");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_EE_ReadECC = (FT_EE_ReadECC_T)GetProcAddress(hModule, "FT_EE_ReadECC"
    );
    if (FT_EE_ReadECC != 0)
      return FT_EE_ReadECC(ftHandle, ucOption, lpwValue);
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_GetQueueStatusEx(FT_HANDLE ftHandle, DWORD * dwRxBytes)
{
  typedef FT_STATUS(WINAPI * FT_GetQueueStatusEx_T)(FT_HANDLE ftHandle,
    DWORD*dwRxBytes);

  HMODULE hModule;
  FT_GetQueueStatusEx_T FT_GetQueueStatusEx;

  OutputDebugStringA("FTD2XX : FT_GetQueueStatusEx");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_GetQueueStatusEx = (FT_GetQueueStatusEx_T)GetProcAddress(hModule,
      "FT_GetQueueStatusEx");
    if (FT_GetQueueStatusEx != 0)
      return FT_GetQueueStatusEx(ftHandle, dwRxBytes);
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_ComPortIdle(FT_HANDLE ftHandle)
{
  typedef FT_STATUS(WINAPI * FT_ComPortIdle_T)(FT_HANDLE ftHandle);

  HMODULE hModule;
  FT_ComPortIdle_T FT_ComPortIdle;

  OutputDebugStringA("FTD2XX : FT_ComPortIdle");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_ComPortIdle = (FT_ComPortIdle_T)GetProcAddress(hModule,
      "FT_ComPortIdle");
    if (FT_ComPortIdle != 0)
      return FT_ComPortIdle(ftHandle);
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_ComPortCancelIdle(FT_HANDLE ftHandle)
{
  typedef FT_STATUS(WINAPI * FT_ComPortCancelIdle_T)(FT_HANDLE ftHandle);

  HMODULE hModule;
  FT_ComPortCancelIdle_T FT_ComPortCancelIdle;

  OutputDebugStringA("FTD2XX : FT_ComPortCancelIdle");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_ComPortCancelIdle = (FT_ComPortCancelIdle_T)GetProcAddress(hModule,
      "FT_ComPortCancelIdle");
    if (FT_ComPortCancelIdle != 0)
      return FT_ComPortCancelIdle(ftHandle);
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_VendorCmdGet(FT_HANDLE ftHandle, UCHAR Request, UCHAR *
  Buf, USHORT Len)
{
  typedef FT_STATUS(WINAPI * FT_VendorCmdGet_T)(FT_HANDLE ftHandle, UCHAR
    Request, UCHAR * Buf, USHORT Len);

  HMODULE hModule;
  FT_VendorCmdGet_T FT_VendorCmdGet;

  OutputDebugStringA("FTD2XX : FT_VendorCmdGet");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_VendorCmdGet = (FT_VendorCmdGet_T)GetProcAddress(hModule,
      "FT_VendorCmdGet");
    if (FT_VendorCmdGet != 0)
      return FT_VendorCmdGet(ftHandle, Request, Buf, Len);
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_VendorCmdSet(FT_HANDLE ftHandle, UCHAR Request, UCHAR *
  Buf, USHORT Len)
{
  typedef FT_STATUS(WINAPI * FT_VendorCmdSet_T)(FT_HANDLE ftHandle, UCHAR
    Request, UCHAR * Buf, USHORT Len);

  HMODULE hModule;
  FT_VendorCmdSet_T FT_VendorCmdSet;

  OutputDebugStringA("FTD2XX : FT_VendorCmdSet");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_VendorCmdSet = (FT_VendorCmdSet_T)GetProcAddress(hModule,
      "FT_VendorCmdSet");
    if (FT_VendorCmdSet != 0)
      return FT_VendorCmdSet(ftHandle, Request, Buf, Len);
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_VendorCmdGetEx(FT_HANDLE ftHandle, USHORT wValue,
  UCHAR*Buf, USHORT Len)
{
  typedef FT_STATUS(WINAPI * FT_VendorCmdGetEx_T)(FT_HANDLE ftHandle, USHORT
    wValue, UCHAR * Buf, USHORT Len);

  HMODULE hModule;
  FT_VendorCmdGetEx_T FT_VendorCmdGetEx;

  OutputDebugStringA("FTD2XX : FT_VendorCmdGetEx");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_VendorCmdGetEx = (FT_VendorCmdGetEx_T)GetProcAddress(hModule,
      "FT_VendorCmdGetEx");
    if (FT_VendorCmdGetEx != 0)
      return FT_VendorCmdGetEx(ftHandle, wValue, Buf, Len);
  }

  return FT_INVALID_HANDLE;
}

FT_STATUS WINAPI FT_VendorCmdSetEx(FT_HANDLE ftHandle, USHORT wValue,
  UCHAR*Buf, USHORT Len)
{
  typedef FT_STATUS(WINAPI * FT_VendorCmdSetEx_T)(FT_HANDLE ftHandle, USHORT
    wValue, UCHAR * Buf, USHORT Len);

  HMODULE hModule;
  FT_VendorCmdSetEx_T FT_VendorCmdSetEx;

  OutputDebugStringA("FTD2XX : FT_VendorCmdSetEx");

  hModule = LoadLibrary(FTD2XX_LIBNAME);
  if (hModule != 0)
  {
    FT_VendorCmdSetEx = (FT_VendorCmdSetEx_T)GetProcAddress(hModule,
      "FT_VendorCmdSetEx");
    if (FT_VendorCmdSetEx != 0)
      return FT_VendorCmdSetEx(ftHandle, wValue, Buf, Len);
  }

  return FT_INVALID_HANDLE;
}
