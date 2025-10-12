# under development
todo:
1. simulation for normal traffic mixed with tcp syn flood (ddos attack). [DONE]
2. snort rules for detecting tcp syn flood. [DONE]
3. traffic control with tc (traffic control) on mininet links, so we get tx, rx errors. [DONE]
4. run simulation for a while - (10hrs?).
5. merge metrics from flow_stats.csv and port_stats.csv
6. Cleaning, feature engineering, labeling.

how to label?:

* snort sees the attack -> alert is created -> scrap timestamp from the alert -> 
attach it into corresponding line from metrics file as a label of the attack.

this way we get dataset for ML model training.

compare few (research needed which ones).

possible improvements in terms of traffic simulation:
1. dns quries, 
2. more specific http traffic (other paths than /), multiple resources
3. failed connections
4. other attacks (syn flood, udp flood, icmp flood, http get flood, slowloris)
5. run concurrent attack and normal traffic (later)