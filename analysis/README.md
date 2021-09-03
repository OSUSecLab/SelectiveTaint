## SPEC:

```
python3 static.py -input ./perlbench_base.i386-m32-gcc42-nn -taintsources read fread fgetc
python3 static.py -input ./bzip2_base.i386-m32-gcc42-nn -taintsources read
python3 static.py -input ./gcc_base.i386-m32-gcc42-nn -taintsources read fread _IO_getc

python3 static.py -input ./mcf_base.i386-m32-gcc42-nn -taintsources fgets
python3 static.py -input ./gobmk_base.i386-m32-gcc42-nn -taintsources _IO_getc fgets
python3 static.py -input ./hmmer_base.i386-m32-gcc42-nn -taintsources fread fgets

python3 static.py -input ./sjeng_base.i386-m32-gcc42-nn -taintsources _IO_getc fgets
python3 static.py -input ./libquantum_base.i386-m32-gcc42-nn -taintsources fread fgetc
python3 static.py -input ./h264ref_base.i386-m32-gcc42-nn -taintsources read fread __isoc99_fscanf

python3 static.py -input ./omnetpp_base.i386-m32-gcc42-nn -taintsources _IO_getc fgets
python3 static.py -input ./astar_base.i386-m32-gcc42-nn -taintsources read fscanf
python3 static.py -input ./Xalan_base.i386-m32-gcc42-nn -taintsources fread _ZNSi4readEPci

python3 static.py -input ./tar -taintsources read fscanf
python3 static.py -input ./gzip -taintsources read _IO_getc
python3 static.py -input ./bzip2 -taintsources fread fgetc
python3 static.py -input ./scp -taintsources read

python3 static.py -input ./cp -taintsources read fscanf
python3 static.py -input ./df -taintsources fscanf
python3 static.py -input ./du -taintsources fscanf
python3 static.py -input ./ln -taintsources fscanf
python3 static.py -input ./ls -taintsources fscanf
python3 static.py -input ./mv -taintsources read fscanf
python3 static.py -input ./rm -taintsources fscanf
python3 static.py -input ./stat -taintsources fscanf

python3 static.py -input ./cat -taintsources read fscanf
python3 static.py -input ./comm -taintsources fscanf
python3 static.py -input ./cut -taintsources fgetc fscanf __fread_chk
python3 static.py -input ./grep -taintsources read fscanf fread_unlocked
python3 static.py -input ./head -taintsources read fscanf
python3 static.py -input ./nl -taintsources fscanf
python3 static.py -input ./od -taintsources fgetc fscanf fread_unlocked __fread_unlocked_chk
python3 static.py -input ./ptx -taintsources fread fscanf
python3 static.py -input ./shred -taintsources fscanf __read_chk fread_unlocked
python3 static.py -input ./tail -taintsources read fscanf
python3 static.py -input ./truncate -taintsources fscanf
python3 static.py -input ./uniq -taintsources fscanf


```


## web applications:

```
python3 static.py -input ./exim -taintsources fgetc fread fscanf __IO_getc recv
python3 static.py -input ./memcached -taintsources read fgets recvfrom
python3 static.py -input ./lighttpd -taintsources read fread
python3 static.py -input ./proftpd -taintsources read fgets __read_chk

python3 static.py -input ./nginx -taintsources read pread64 readv recv

python3 static.py -input ./lynx -taintsources read fread fgetc fgets _IO_getc wgetch readlink
```

## other applications:

```
python3 static.py -input ./sox -taintsources  read  fread  fgets  _IO_getc  __isoc99_scanf  __isoc99_fscanf 
python3 static.py -input ./tt++ -taintsources  read  fread  fgets  _IO_getc  gnutls_record_recv  fgetc 
python3 static.py -input ./mxmldoc-static -taintsources  read  _IO_getc __fread_chk
python3 static.py -input ./dcraw -taintsources  fread  fscanf __fread_chk _IO_getc  fgets  jpeg_read_header 
python3 static.py -input ./gif2tga -taintsources  fread  _IO_getc 
python3 static.py -input ./gravity -taintsources  read  getline 
python3 static.py -input ./ncurses -taintsources  read  fread  fgets  fgetc 
python3 static.py -input ./lame -taintsources  fread  _IO_getc __fread_chk
python3 static.py -input ./mp3gain -taintsources  fread  _IO_getc 
python3 static.py -input ./tiffsplit -taintsources  read  jpeg_read_header  jpeg_read_raw_data 
python3 static.py -input ./nasm -taintsources  fread  fgets  fgetc 
python3 static.py -input ./tjbench-static -taintsources  fread  _IO_getc __fread_chk
python3 static.py -input ./opj_compress -taintsources  fread  _IO_getc  fgets  fgetc  __isoc99_fscanf  png_read_image 
python3 static.py -input ./jhead -taintsources  fread  fgetc 
```

## dependencies

install ipython3 if needed
