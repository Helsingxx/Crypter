#include <windows.h>

void XOR(char *Data, LONGLONG sz) {
   char Key[] = "EncryptionKey";
   
   for (int i = 0; i < sz; i++)
      Data[i] = Data[i] ^ Key[i % strlen(Key)];
}

int main()
{
// memory map of binary
LONGLONG sz;
HANDLE hfile = CreateFileA("test.exe", GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
if (hfile == INVALID_HANDLE_VALUE)
{
	printf("Error opening file.");
   return 1;
}
HANDLE filemapping = CreateFileMappingA(hfile, 0, PAGE_READWRITE, 0, 0, 0);
//add: reject files with size = 0
if (filemapping == NULL)
{
	printf("Error creating file mapping.");
   return 2;
}
void * startoffile = MapViewOfFile(filemapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);
if (startoffile == NULL)
{
	printf("Error mapping into view.");
   return 3;
}
sz = GetFileSize(hfile, NULL);


XOR(startoffile, sz);

FlushViewOfFile(startoffile, 0);
printf("success.\n");
}