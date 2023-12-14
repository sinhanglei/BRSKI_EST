

# EST and BRSKI in Python - DEMO project

## A DEMO project written in Python implementing EST and BRSKI including a client that may utilize either enrollment protocol.

This project is an example of how to implement a EST and a BRSKI in Python, so that clients may either enroll via EST or BRSKI. 

The client either sends an enrollment request to the Proxy. The enrollment request is either for EST or BRSKI enrollment. In the case of EST, the request is simply forwarded to the EST-Server. In the case of BRSKI, the proxy functions as a registrar and forwards the message accordingly to the BRSKI-Server, which also called the MASA. The response returns the same way back.

 ```mermaid
 graph TD;
 A(Client) <--> B(Proxy);
 B <-->C(EST)
 B <-->D(BRSKI);
 ```

 # How to use the demo
 1. Execute MASA/bin/scripts/main_masa.py
 2. Execute EST/bin/scripts/est.py
 3. Execute Proxy/bin/scripts/proxy.py
 4. Either execute Client/bin/scripts/enroll_brski.py or
 execute Client/bin/scripts/enroll_est.py

