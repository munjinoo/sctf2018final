## Description
tpk파일은 zip파일이기 때문에 압축을 풀 수 있고 bin 안에 가보면 실행파일이 하나 들어가 있다.

해당 파일을 리버싱해보면 yaca라는 라이브러리를 이용하여 무언가 decrypt를 진행하는 것을 확인할 수 있다. 이 부분을 똑같이 진행해보면 플래그를 얻을 수 있다.

이때 IDA로 보면 인자가 숫자로만 보이기때문에 어떤 암호화방식을 이용했는지 알 수 없으므로 TIZEN 공식 문서를 이용하거나 github에서 소스코드를 확인하면 된다.

app의 id, label, metadata등 을 가져오는 것은 모두 tizen-manifest.xml에 있다.

