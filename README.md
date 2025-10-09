# under development
todo:
1. simulation for normal traffic mixed with tcp syn flood (ddos attack).
2. snort rules for detecting tcp syn flood.
3. traffic control with tc (traffic control) on mininet links, so we get tx, rx errors.
4. run simulation for a while - (10hrs?).
5. merge metrics from flow_stats.csv and port_stats.csv
6. Cleaning, feature engineering, labeling.

how to label?:

* snort sees the attack -> alert is created -> scrap timestamp from the alert -> 
attach it into corresponding line from metrics file as a label of the attack.

this way we get dataset for ML model training.

compare few (research needed which ones).