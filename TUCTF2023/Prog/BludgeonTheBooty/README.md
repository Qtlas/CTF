<h1> Bludgeon The Booty : Medium </h1>

<p> In this challenge we have to brute force, a key of 3 lengths only contains numbers, and for this we have to increment the values ​​like on a padlock </p>

```python
import socket


def add(s : socket.socket, index : int) -> None:
    "Add 1 to the given index"

    s.send('1\n'.encode())
    s.recv(256).decode()

    s.send((str(index) +'\n').encode())
    s.recv(256).decode()

    s.send((str('+') + '\n').encode())
    msg = s.recv(2048).decode()

    if msg.find('The chest is still locked!') == -1:  #If we find the key
        print(msg)
        exit(0)


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server_addr = "chal.tuctf.com"
server_port = 30002

s.connect((server_addr, server_port))

while True:
    data = s.recv(256).decode()

    #Brute force the 3 length key
    for i in range(10):
        for l in range(10):
            for _ in range(10):
                add(s, 3)
            add(s, 2)
        add(s, 1)
```

<p> This can be taking a while, but after few minutes we got him ! </p>

```
  ___________
 /           \
/___|7|2|7|___\
|      @      |
|_____________|
You have unlocked the treasure chest!
You have found the Flag!
--------------------------\  
|   .        .             \
|    .  . .     .           \
|                  X         |
>                            |
|  TUCTF{h3R3_1!3_M3_800Ty}  |
|                            |
>                            <
|                            |
-----^-----------------^------
```
