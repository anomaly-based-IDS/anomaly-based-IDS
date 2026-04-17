"""
pcap/csv 로 읽어옴
-> reader에서 flowRecord 형식으로 변환
-> flowRecord에서 feature를 isolation forest 모델로 전달
-> .predict(feature)로 공격탐지해서 flush로 탐지된 id 전달
-> attack writer가 기록

"""