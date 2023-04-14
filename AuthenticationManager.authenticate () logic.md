``` java
 AuthenticationManager authenticationManager = authenticationManagerBuilder.getObject();
 Authentication authenticate = authenticationManager.authenticate(authenticationToken);
```  

여기서 authenticate()를 호출 하면 spring의 `ProviderManager.authenticate()`가 호출된다.  

![image](https://user-images.githubusercontent.com/67637716/231921418-9aa5a4b1-7c0a-4795-94c9-d7541491353b.png)  

여기서 provider는 `DaoAuthenticationProvider`  

interface AuthenticationProvider > abstract class AbstractUserDetailsAuthenticationProvider > class DaoAuthenticationProvider  

AbstractUserDetailsAuthenticationProvider의 authenticate()가 호출됨.  


![image](https://user-images.githubusercontent.com/67637716/231922188-d88c359e-f22f-482b-8020-bcad219d1cfa.png)  

``` java
user = retrieveUser(username, (UsernamePasswordAuthenticationToken) authentication);
```  
위 코드에서 retrieveUser는 `DaoAuthenticationProvider`에서 호출이 된다.  

![image](https://user-images.githubusercontent.com/67637716/231922354-160c440f-f39c-4d37-bbbd-5a184d573b73.png)  

여기서 드디어 loadUserByUsername()가 호출이 됨.  

![image](https://user-images.githubusercontent.com/67637716/231922428-c84687fd-6f12-43a3-b316-0613f89b4827.png)  



 



