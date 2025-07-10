
![peekab0x0_banner](https://github.com/user-attachments/assets/1c4f1625-b63f-43fe-8508-305c01dae813)




1. From your C2 of choice make a x64 EXE and get it into this project file
2. Add your keys where you are asked to in the format seen in the project
3. run ./donut.exe --input=C2payload.exe --arch 2 --format 1 --bypass 3 -o sc.bin 
4. run that sc.bin through the python AES to get the payload.h file u will need this file when we compile the finial executable
5. if u cant do this last part. you have better use of your time learning the basics. Compile the project in cl with admin VS tools x64 and vallaaa.
![loaderimage](https://github.com/user-attachments/assets/873d877e-d896-4539-9477-f656bce16906)

Windows defender will wine a little bit but its too late.... you are in memory and in full controal. feel free to add to this or change it. 
im not responsable for any misuse of this project. use at your own risk and use on only systems you have permission to. i didnt create the donut.exe. look into it further if you like it! https://github.com/TheWover/donut
thanks! i may add another version where encryption keys are grabbed from a hosting area and then decrypted once keys are grabbed. i have it but wanted to just leave this one for now. 
