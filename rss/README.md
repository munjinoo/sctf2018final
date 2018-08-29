## Exploit
concat 메뉴에서 int + int를 처리하는 과정에서 버그가 발생함
이를 이용해서 두개의 int를 합치면 원하는 주소를 가르키는 string으로 바꿀 수 있음
got table 주소로 바꿔서 libc leak을 하고 free함수의 got를 system으로 덮음
system의 주소를 넣어줄때 그냥 하면 주소가 이상하게 들어가기 때문에 substr 메뉴를 이용해서 free got의 길이를 0으로 만들어주고 합쳐줘야함
concat 메뉴에서 합쳤을때 string의 길이가 0x100을 넘어가면 새로 할당했던 heap chunk를 free시키기때문에 /bin/sh를 인자로 넘겨줄 수 있음
