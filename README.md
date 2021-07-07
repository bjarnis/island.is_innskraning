# island.is_innskraning
Saml 2 - Innskráning fyrir island.is í Java

### Uppfært eftir island.is þjónusturof 03.07.2021
[Sjá upplýsingar https://island.is/rof-innskraning/leidbeiningar-fyrir-taeknifolk](https://island.is/rof-innskraning/leidbeiningar-fyrir-taeknifolk)
&nbsp;

&nbsp;
```java
KeyStore keystore = KeyStore.getInstance("JKS");
try (InputStream is = Files.newInputStream(Paths.get("./Audkenni_ca_Kedja.jks"))) {
    keystore.load(is, "password".toCharArray());
}

String samlString = "%result.body_token%";
String userIP = "%user_ip%";
String authId = null; // null to not validate auth_id
String restrictedAudience = "undirlen.bjarni.net";

IslandIsSaml20Authentication isauth = new IslandIsSaml20Authentication(keystore);
Map<String, String> map = isauth.validateSaml(samlString, userIP, authId, restrictedAudience);
for (Entry<String, String> entry : map.entrySet()) {
    System.out.println(entry.getKey() + " = " + entry.getValue() + "\n");
}
```
