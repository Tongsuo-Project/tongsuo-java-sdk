# JCE Examples

Every example in this directory is a standalone example that demonstrates how to use the JCE API in Tongsuo OpenJDK.
The example depends on tongsuo-openjdk. You need to build tongsuo-openjdk or download it from maven repository.
Take TLS13Client and TLS13Server as an example.

## TLS13Client

```shell
javac -cp openjdk/build/libs/tongsuo-openjdk-<version>-<os>-<arch>.jar examples/jce/TLS13Client.java

java -cp examples/jce:openjdk/build/libs/tongsuo-openjdk-<version>-<os>-<arch>.jar TLS13Client
```

## TLS13Server

TLS13Server depends on bouncycastle and tongsuo-openjdk. You need to download bcprov-jdk from maven repository.

Note: sm2.crt, sm2.key and chain.crt are required to run the server.

```shell
cd examples/jce

javac -cp ~/.m2/repository/org/bouncycastle/bcprov-jdk15on/1.69/bcprov-jdk15on-1.69.jar:../../openjdk/build/libs/tongsuo-openjdk-<version>-<os>-<arch>.jar  TLS13Server.java

java -cp .:/path/to/user/.m2/repository/org/bouncycastle/bcprov-jdk15on/1.69/bcprov-jdk15on-1.69.jar:../../openjdk/build/libs/tongsuo-openjdk-<version>-<os>-<arch>.jar TLS13Server
```
