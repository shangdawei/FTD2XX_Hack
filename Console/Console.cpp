// Console.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"

#define FTD2XX_HACK ( 1 )

#if ( FTD2XX_HACK > 0 )

#ifndef _WIN64
#pragma comment(lib, "..\\Debug\\FTD2XX_Hack.lib")
#else
#pragma comment(lib, "..\\x64\\Debug\\FTD2XX_Hack.lib")
#endif

#include "..\\FTD2XX_Hack\FTD2XX_Hack.h"

#else

#ifndef _WIN64
#pragma comment(lib, "library_x86\\ftd2xx.lib")
#else
#pragma comment(lib, "library_x64\\ftd2xx.lib")
#endif

#include "ftd2xx.h"

#endif




int main()
{
	FT_HANDLE fthandle;
	FT_STATUS res;
  char buffer[256];
  DWORD count;

	res = FT_Open(0, &fthandle);
	if (res != FT_OK)
	{

		printf("opening failed! error %d\r\n", res);
		printf("press any key to exit.\r\n");
		getchar();
		return 1;
	}

  for (DWORD i = 0; i < 256; i++)
    buffer[i] = i;

  DWORD writeIndex = 0;
  DWORD writeCount = 5;
  FT_Write(fthandle, &buffer[writeIndex], writeCount, &count);
  writeIndex += writeCount;

  writeCount = 15;
  FT_Write(fthandle, &buffer[writeIndex], writeCount, &count);
  writeIndex += writeCount;

  writeCount = 15;
  FT_Write(fthandle, &buffer[writeIndex], writeCount, &count);
  writeIndex += writeCount;

  FT_Read(fthandle, buffer, 256, &count);

  writeCount = 15;
  FT_Write(fthandle, &buffer[writeIndex], writeCount, &count);
  writeIndex += writeCount;

  FT_Read(fthandle, buffer, 256, &count);

  FT_Close(fthandle);

	printf("Hello!\r\n");
	printf("press any key to exit.\r\n");
	getchar();

	return 0;
}


