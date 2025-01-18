<p align="center">
    <img src="./banner.png">
    <h1 align="center">EnigmaScope</h1>
    <p align="center">EnigmaScope is a Python utility that hides files in any kind of another file. This tool is ideal for cybersecurity enthusiasts, ethical hackers, and anyone looking to protect sensitive information.
     <h1 align="center">Youtube Video</h1>
    <a href="https://www.youtube.com/watch?v=5RIibpcbWHc"><img src="https://img.youtube.com/vi/5RIibpcbWHc/maxresdefault.jpg"></a>
</p>
</p>

#### Installation
- Clone the repository and install the necessary dependencies:

```bash
git clone https://github.com/madhanmaaz/EnigmaScope.git
cd EnigmaScope
pip install -r requirements.txt
```

> [!IMPORTANT]
> - When the file gets edited, all secure contents of the file are lost.
> - There is no recovery option if you forget the password.

#### Usage
1. Load an Image File.

- To load an image file and set a password, use:
```bash
python EnigmaScope.py --load secure.png
```

2. Display the Help Menu.
- To see available commands, type:
```bash
[secure.png]> help

+======== COMMANDS ========+
help        Help menu.
q           Exit.

list        List all files.
write       <URL or FILE>   ex: write /path/to/file, write https://example.com/data.zip
read        <ID or *>       ex: read 0, read *
delete      <ID or *>       ex: delete 0, delete *
```

3. Add a File.
- To add a file to the image, use:
```bash
[secure.png]> write path/to/passwords.txt
[+] write 'passwords.txt' successfully.
```

4. List Files.
- To list all files embedded in the image, use:
```bash
[secure.png]> list

  ID  FILE                      TIME                          SIZE
----  ------------------------  --------------------------  ------
   0  passwords.txt             2024-05-14 13:37:01.556315    0
   1  elonmusk.mp4              2024-05-14 13:38:20.250163    4.05
   2  ironman.mp3               2024-05-14 13:40:02.469420    0.43
   3  deadpool.jpg              2024-05-14 13:40:42.439906    0.08
   4  c4611_sample_explain.pdf  2024-05-14 13:41:26.543092    0.08
```

5. Read a File.
- To read a file, specify its ID:
```bash
[secure.png]> read 0
[+] Read success. saved on 'c:\users\username\documents\enigmascope\secure\passwords.txt'
```

5. Delete a File.
- To delete a file, specify its ID:
```bash
[secure.png]> delete 0
[+] file 'passwords.txt' deleted successfully.
```

#### Testing with a Dragon Wallpaper
- For example, the below wallpaper image (`secure.png`) contains files like `txt`, `pdf`, `mp4`, `mp3`, etc. To test, use the dragon wallpaper secure.png. The password is 123.
- Run - `python EnigmaScope.py -l secure.png`

![test image](./secure.png)

![terminal](scr/terminal.png)

