# Compression

### HTTP Compression

Compression can be applied at the application layer level. In a web 
context, this means applying compression at the HTTP level. More 
specifically, HTTP requests can be compressed by the webserver. This is 
indicated by the `Content-Encoding` HTTP header. This header can be set to the values `gzip`, `compress`, or `deflate` to inform the web browser what kind of compression method was used to compress the data. The web browser is then able to unpack the compressed data and display the web page correctly.

If compression is applied at the HTTP level, the compressed response looks similar to this:

![image.png](Compression/image.png)

**Note:** Most proxies like Burp automatically detect compressed responses and unpack the response by default. So to view the compressed response, this option needs to be disabled.

### **TLS Compression**

Instead of applying compression at the application layer level, it can also be applied at the TLS level. This means that not only the application layer payload but all application layer data is compressed. In a web context, this means that the whole response is compressed, including all HTTP headers.

Since the compression is applied at the TLS level, it is completely transparent to any web server or web proxy such that we cannot detect it in Burp. However, whether TLS compression is used or not is negotiated in the TLS handshake.

We can see the compression methods supported by the client in the `ClientHello` message in the `Compression Methods` Field:

![image.png](Compression/image%201.png)

The compression method is then chosen by the server in the `ServerHello` message:

![image.png](Compression/image%202.png)