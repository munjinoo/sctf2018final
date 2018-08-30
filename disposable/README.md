## Description
대회 당시에 uninitialized 문제도 파악했고 fs레지스터를 이용해서 실행시마다 스택주소가 변하므로 이를 이용해서 돌려보면서 적당한 주소값을 이용하면 된다는 것 까지 알았다. 하지만 이미 있는 값말고 내 입력을 이용하여 원하는 주소 아무곳이나 사용할 수 있었으면해서 그것을 시도하다가 제대로 맞추지 못하고 끝나버렸다.

이번에 다시 풀어보니 어떻게하면 적당한 포인터를 이용할 수 있는지 알고 시작한 채로도 꽤나 삽질했다. 아마 대회때 찾아냈더라도 시간내에 풀지 못했을 수도 있다는 생각을 했다.

해당 문제는 자유롭게 원하는 주소에 값을 입력할 수 있는 함수가 `scanf`밖에 없기때문에 PC control이 됐더라도 익스하는데 꽤나 불편했다. 특히, got table의 주소에 꼭 0x20이 들어가기때문에 이를 우회할 필요가 있었다.

## Exploit
취약점은 send메뉴와 login메뉴에서 발생하는 uninitialized문제다. 해당 익스는 send메뉴의 취약점만 이용했다. 로그인하고 나서 2번메뉴를 7번 실행시키고 send로 가면 스택을 가리키고 있는 포인터를 이용할 수 있게되고 이곳에 login하고 진입하는 함수(앞으로 `inmenu`라고 칭함)의 return address를 덮을 수 있다.

이 return address위쪽에는 우리가 입력해준 비밀번호가 들어가기 때문에 비밀번호를 ROP체인으로 설정하고 return address에 ppr 가젯을 넣어주면 우리가 비밀번호로 넣어줬던 ROP체인을 실행시킬 수 있다.

첫번째 ROP로 bss영역에 새로운 ROP체인을 넣고 이곳으로 넘어가는 체인을 넣어줬다. 여기서 한번 삽질을 했는데 비밀번호는 최대 65글자이기 때문에 rdi와 rsi를 세팅하고 scanf를 실행시킨뒤 `pop rbp; ret; leave; ret` 가젯까지 모두 넣어주기엔 공간이 부족했다.

여기서 비밀번호가 bss영역에 들어가는데 먼저 bss로 뛰지 않았냐는 질문이 생길 수 있는데 scanf내부에서 0x600~0x700정도의 스택공간을 사용하기 때문에 write권한이 없어 Segmentation fault가 발생해버린다.

공간이 부족한 문제를 해결하기위해 스택에 원하는 주소를 올려놓고 `$`라는 특수문자를 이용했다. `pop rsi`가젯이 정확하게는 `pop rsi; pop r15; ret`이기 때문에 rsi세팅에 0x18만큼의 공간이 소비된다. 스택에 올려버리면 이만큼의 공간을 확보할 수 있어서 bss 영역으로 넘어가는 체인까지 가능해진다.

bss영역의 주소는 상당히 높게 잡았는데 앞에서 말했듯이 scanf에서 스택을 크게 잡기때문에 세그폴을 피하기 위함이다.

bss영역에서의 ROP체인은 libc릭을 하고 scanf를 통해 `system("/bin/sh")`을 받아내는 과정이다.

여기서 printf함수가 사용되었는데 got주소가 전부 0x20을 포함하기때문에 처음에 다른 주소를 넣어주고`%n`을 이용해서 제대로된 주소로 바꿔주기 위함이다.

그리고 중간에 의미없는 `ret`가젯이 들어갔는데 이는 `scanf("%s")`가 실행되는 중에 xmm레지스터를 사용해서 alignment가 맞지 않으면 터지기때문에 이를 위해 들어갔다. 이런 현상을 처음 겪어봐서 당황스러웠다.